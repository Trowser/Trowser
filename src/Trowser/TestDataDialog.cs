using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace Trowser;

/// <summary>
/// Dialog for managing test data strings and security payloads. Dark-themed to match the Trowser UI.
/// Provides toggles for online/offline mode and ASCII-only filtering,
/// tabbed selection between test strings and payloads, a scrollable list with remove buttons, and an add row.
/// </summary>
public class TestDataDialog : Window
{
    private readonly TestDataService _service;
    private readonly ToggleButton _onlineToggle;
    private ToggleButton _asciiToggle = null!;
    private readonly TextBox _onlineUrlTextBox;
    private readonly StackPanel _listPanel;
    private readonly TextBox _addTextBox;
    private readonly ScrollViewer _listScrollViewer;
    private readonly TextBlock _listHeader;
    private readonly ToggleButton _stringsTabButton;
    private readonly ToggleButton _payloadsTabButton;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentOn = Bc("#0E639C");
    private static readonly SolidColorBrush AccentOff = Bc("#555555");
    private static readonly SolidColorBrush ThumbColor = Bc("#FFFFFF");
    private static readonly SolidColorBrush DisabledTrack = Bc("#3A3A3A");
    private static readonly SolidColorBrush DisabledThumb = Bc("#666666");

    public TestDataDialog(Window owner, TestDataService service)
    {
        _service = service;
        Owner = owner;
        Title = "Test Data";
        Width = 600;
        Height = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        MinWidth = 400;
        MinHeight = 350;
        Background = BgMedium;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // ── Top: Toggles ──
        var togglePanel = new StackPanel { Margin = new Thickness(20, 16, 20, 8) };

        var onlineRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        _onlineToggle = CreateSwitchToggle(service.UseOnline);
        onlineRow.Children.Add(_onlineToggle);
        onlineRow.Children.Add(new TextBlock
        {
            Text = "Online",
            Foreground = FgText,
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(10, 0, 0, 0)
        });
        onlineRow.Children.Add(new TextBlock
        {
            Text = "— fetch random strings from an online source (test strings only)",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0)
        });
        togglePanel.Children.Add(onlineRow);

        _onlineUrlTextBox = new TextBox
        {
            Text = service.OnlineUrl,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 28,
            Margin = new Thickness(52, 0, 0, 6),
            Visibility = service.UseOnline && service.ActiveKind == TestDataKind.Strings
                ? Visibility.Visible
                : Visibility.Collapsed
        };
        togglePanel.Children.Add(_onlineUrlTextBox);

        var asciiRow = new StackPanel { Orientation = Orientation.Horizontal };
        _asciiToggle = CreateSwitchToggle(service.AsciiOnly);
        _asciiToggle.IsEnabled = !service.UseOnline || service.ActiveKind == TestDataKind.Payloads;
        asciiRow.Children.Add(_asciiToggle);
        asciiRow.Children.Add(new TextBlock
        {
            Text = "ASCII only",
            Foreground = FgText,
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(10, 0, 0, 0)
        });
        asciiRow.Children.Add(new TextBlock
        {
            Text = "— only select from ASCII entries (offline only)",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0)
        });
        togglePanel.Children.Add(asciiRow);

        _onlineToggle.Checked += (_, _) => UpdateOnlineControls();
        _onlineToggle.Unchecked += (_, _) => UpdateOnlineControls();

        Grid.SetRow(togglePanel, 0);
        rootGrid.Children.Add(togglePanel);

        // ── Tabs ──
        var tabPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(20, 0, 20, 8)
        };
        _stringsTabButton = CreateTabButton("Test Strings", service.ActiveKind == TestDataKind.Strings);
        _payloadsTabButton = CreateTabButton("Payloads", service.ActiveKind == TestDataKind.Payloads);
        _stringsTabButton.Click += (_, _) => SelectKind(TestDataKind.Strings);
        _payloadsTabButton.Click += (_, _) => SelectKind(TestDataKind.Payloads);
        tabPanel.Children.Add(_stringsTabButton);
        tabPanel.Children.Add(_payloadsTabButton);

        Grid.SetRow(tabPanel, 1);
        rootGrid.Children.Add(tabPanel);

        // ── Middle: Scrollable list ──
        _listHeader = new TextBlock
        {
            Foreground = Bc("#569CD6"),
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(20, 4, 20, 6)
        };
        var headerAndList = new DockPanel();
        DockPanel.SetDock(_listHeader, Dock.Top);
        headerAndList.Children.Add(_listHeader);

        _listPanel = new StackPanel();
        _listScrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(20, 0, 20, 0),
            Content = _listPanel
        };
        headerAndList.Children.Add(_listScrollViewer);

        Grid.SetRow(headerAndList, 2);
        rootGrid.Children.Add(headerAndList);

        // ── Add row ──
        var addRow = new Grid { Margin = new Thickness(20, 8, 20, 8) };
        addRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        addRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _addTextBox = new TextBox
        {
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
        _addTextBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) AddCurrentText();
        };
        Grid.SetColumn(_addTextBox, 0);
        addRow.Children.Add(_addTextBox);

        var addButton = new Button
        {
            Content = "Add",
            Width = 60,
            Height = 30,
            Margin = new Thickness(6, 0, 0, 0),
            Background = AccentOn,
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand
        };
        addButton.Click += (_, _) => AddCurrentText();
        Grid.SetColumn(addButton, 1);
        addRow.Children.Add(addButton);

        Grid.SetRow(addRow, 3);
        rootGrid.Children.Add(addRow);

        // ── Bottom: Close button ──
        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(20, 4, 20, 14)
        };
        var closeButton = new Button
        {
            Content = "Close",
            Width = 90,
            Height = 28,
            IsCancel = true,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand
        };
        closeButton.Click += (_, _) => Close();
        buttonPanel.Children.Add(closeButton);

        Grid.SetRow(buttonPanel, 4);
        rootGrid.Children.Add(buttonPanel);

        Content = rootGrid;

        RebuildList();
        UpdateTabButtons();
        UpdateOnlineControls();

        Closing += (_, _) =>
        {
            _service.UseOnline = _onlineToggle.IsChecked == true;
            _service.AsciiOnly = _asciiToggle.IsChecked == true;
            _service.OnlineUrl = _onlineUrlTextBox.Text.Trim();
            _service.Save();
        };
    }

    private void SelectKind(TestDataKind kind)
    {
        if (_service.ActiveKind == kind)
            return;

        _service.ActiveKind = kind;
        UpdateTabButtons();
        UpdateOnlineControls();
        RebuildList();
    }

    private void UpdateTabButtons()
    {
        StyleTabButton(_stringsTabButton, _service.ActiveKind == TestDataKind.Strings);
        StyleTabButton(_payloadsTabButton, _service.ActiveKind == TestDataKind.Payloads);
    }

    private void UpdateOnlineControls()
    {
        var isStrings = _service.ActiveKind == TestDataKind.Strings;
        var online = _onlineToggle.IsChecked == true;

        _onlineToggle.IsEnabled = isStrings;
        _onlineUrlTextBox.Visibility = isStrings && online ? Visibility.Visible : Visibility.Collapsed;
        _asciiToggle.IsEnabled = !online || !isStrings;
    }

    private void AddCurrentText()
    {
        var text = _addTextBox.Text;
        if (string.IsNullOrEmpty(text)) return;

        _service.AddEntry(text);
        _addTextBox.Clear();
        _addTextBox.Focus();
        RebuildList();
    }

    private void RebuildList()
    {
        _listPanel.Children.Clear();
        foreach (var entry in _service.Entries)
        {
            _listPanel.Children.Add(CreateEntryRow(entry));
        }

        var label = _service.ActiveKind == TestDataKind.Strings ? "Test strings" : "Payloads";
        _listHeader.Text = $"{label} ({_service.Entries.Count})";
    }

    private Border CreateEntryRow(TestStringEntry entry)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var displayText = entry.Text.Replace("\r\n", "\\r\\n").Replace("\n", "\\n").Replace("\t", "\\t");

        var textBlock = new TextBlock
        {
            Text = displayText,
            Foreground = entry.IsAscii ? FgText : Bc("#CE9178"),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis,
            ToolTip = entry.Text,
            Margin = new Thickness(8, 0, 8, 0)
        };
        Grid.SetColumn(textBlock, 0);
        grid.Children.Add(textBlock);

        var copyButton = new Button
        {
            Content = "\uD83D\uDCCB",
            Width = 24,
            Height = 24,
            Background = Brushes.Transparent,
            Foreground = FgDim,
            BorderThickness = new Thickness(0),
            FontSize = 11,
            Cursor = Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0),
            ToolTip = "Copy to clipboard"
        };
        copyButton.Click += (_, _) =>
        {
            Clipboard.SetText(entry.Text);
            copyButton.Content = "\u2713";
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(800) };
            timer.Tick += (_, _) => { copyButton.Content = "\uD83D\uDCCB"; timer.Stop(); };
            timer.Start();
        };
        Grid.SetColumn(copyButton, 1);
        grid.Children.Add(copyButton);

        var removeButton = new Button
        {
            Content = "\u2715",
            Width = 24,
            Height = 24,
            Background = Brushes.Transparent,
            Foreground = FgDim,
            BorderThickness = new Thickness(0),
            FontSize = 12,
            Cursor = Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 4, 0),
            ToolTip = "Remove"
        };
        removeButton.Click += (_, _) =>
        {
            _service.RemoveEntry(entry);
            RebuildList();
        };
        Grid.SetColumn(removeButton, 2);
        grid.Children.Add(removeButton);

        var border = new Border
        {
            Child = grid,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(0, 4, 0, 4)
        };

        border.MouseEnter += (_, _) => border.Background = Bc("#2A2D2E");
        border.MouseLeave += (_, _) => border.Background = BgDark;

        return border;
    }

    private static ToggleButton CreateTabButton(string label, bool selected)
    {
        var button = new ToggleButton
        {
            Content = label,
            IsChecked = selected,
            MinWidth = 120,
            Height = 28,
            Margin = new Thickness(0, 0, 4, 0),
            Padding = new Thickness(12, 0, 12, 0),
            FontSize = 12,
            Cursor = Cursors.Hand,
            BorderThickness = new Thickness(1),
            BorderBrush = BorderClr
        };
        StyleTabButton(button, selected);
        return button;
    }

    private static void StyleTabButton(ToggleButton button, bool selected)
    {
        button.IsChecked = selected;
        button.Background = selected ? AccentOn : BgDark;
        button.Foreground = selected ? Brushes.White : FgText;
    }

    private static ToggleButton CreateSwitchToggle(bool isOn)
    {
        const double trackWidth = 40;
        const double trackHeight = 20;
        const double thumbSize = 16;
        const double thumbMargin = 2;
        double thumbOffX = thumbMargin;
        double thumbOnX = trackWidth - thumbSize - thumbMargin;

        var track = new Border
        {
            Width = trackWidth,
            Height = trackHeight,
            CornerRadius = new CornerRadius(trackHeight / 2),
            Background = isOn ? AccentOn : AccentOff
        };

        var thumb = new Ellipse
        {
            Width = thumbSize,
            Height = thumbSize,
            Fill = ThumbColor,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(isOn ? thumbOnX : thumbOffX, 0, 0, 0)
        };

        track.Child = thumb;

        var toggle = new ToggleButton
        {
            IsChecked = isOn,
            Width = trackWidth,
            Height = trackHeight,
            Cursor = Cursors.Hand,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Content = track,
            Padding = new Thickness(0)
        };

        toggle.Template = CreateTransparentToggleTemplate();

        void UpdateVisuals(bool on, bool enabled)
        {
            if (!enabled)
            {
                track.Background = DisabledTrack;
                thumb.Fill = DisabledThumb;
            }
            else
            {
                track.Background = on ? AccentOn : AccentOff;
                thumb.Fill = ThumbColor;
            }

            var targetX = on ? thumbOnX : thumbOffX;
            var animation = new ThicknessAnimation(
                new Thickness(targetX, 0, 0, 0),
                TimeSpan.FromMilliseconds(150))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
            thumb.BeginAnimation(MarginProperty, animation);
        }

        toggle.Checked += (_, _) => UpdateVisuals(true, toggle.IsEnabled);
        toggle.Unchecked += (_, _) => UpdateVisuals(false, toggle.IsEnabled);
        toggle.IsEnabledChanged += (_, _) => UpdateVisuals(toggle.IsChecked == true, toggle.IsEnabled);

        return toggle;
    }

    private static ControlTemplate CreateTransparentToggleTemplate()
    {
        const string xaml = """
            <ControlTemplate TargetType="ToggleButton"
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" />
            </ControlTemplate>
            """;
        return (ControlTemplate)XamlReader.Parse(xaml);
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
