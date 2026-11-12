using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Modeless dialog for session-wide WebView2 request header overrides.
/// Each enabled row replaces the header if present, or adds it if missing.
/// </summary>
public class HeaderOverrideDialog : Window
{
    private readonly StackPanel _rowsList;
    private readonly TextBox _nameBox;
    private readonly TextBox _valueBox;

    public event Action? OverridesChanged;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");

    public HeaderOverrideDialog(Window owner)
    {
        Owner = owner;
        Title = "Header Overrides";
        Width = 520;
        Height = 480;
        MinWidth = 400;
        MinHeight = 320;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(0)
        };

        var root = new StackPanel { Margin = new Thickness(20, 16, 20, 8) };

        root.Children.Add(new TextBlock
        {
            Text = "Header Overrides",
            Foreground = AccentBlue,
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        });
        root.Children.Add(new TextBlock
        {
            Text = "Applied to every WebView2 request (browsing, in-page fetch, Send Browser). " +
                   "Replace if the header exists, add if it does not. " +
                   "Send (Direct), Raw, and server-side APIs ignore these. " +
                   "Chromium may refuse Host, Connection, Content-Length, and the cookie jar.",
            Foreground = FgDim,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        });

        _rowsList = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        root.Children.Add(_rowsList);

        var addGrid = new Grid { Margin = new Thickness(0, 4, 0, 0) };
        addGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(160) });
        addGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        addGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _nameBox = CreateTextBox("User-Agent");
        _nameBox.ToolTip = "Header name";
        Grid.SetColumn(_nameBox, 0);
        addGrid.Children.Add(_nameBox);

        _valueBox = CreateTextBox("");
        _valueBox.Margin = new Thickness(4, 0, 0, 0);
        _valueBox.ToolTip = "Header value";
        Grid.SetColumn(_valueBox, 1);
        addGrid.Children.Add(_valueBox);

        var addBtn = CreateSmallButton("Add", AccentGreen);
        addBtn.Margin = new Thickness(6, 0, 0, 0);
        addBtn.Click += Add_Click;
        Grid.SetColumn(addBtn, 2);
        addGrid.Children.Add(addBtn);
        root.Children.Add(addGrid);

        var addLabels = new Grid { Margin = new Thickness(0, 1, 0, 0) };
        addLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(160) });
        addLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        AddMicroLabel(addLabels, "Name", 0);
        AddMicroLabel(addLabels, "Value", 1, new Thickness(4, 0, 0, 0));
        root.Children.Add(addLabels);

        scroll.Content = root;
        Grid.SetRow(scroll, 0);
        rootGrid.Children.Add(scroll);

        var bottomBar = new DockPanel { Margin = new Thickness(20, 8, 20, 12) };
        var closeBtn = CreateStyledButton("Close");
        closeBtn.Click += (_, _) => Close();
        DockPanel.SetDock(closeBtn, Dock.Right);
        bottomBar.Children.Add(closeBtn);

        var leftPanel = new StackPanel { Orientation = Orientation.Horizontal };
        var clearBtn = CreateSmallButton("Clear all", AccentRed);
        clearBtn.Click += Clear_Click;
        leftPanel.Children.Add(clearBtn);
        DockPanel.SetDock(leftPanel, Dock.Left);
        bottomBar.Children.Add(leftPanel);

        Grid.SetRow(bottomBar, 1);
        rootGrid.Children.Add(bottomBar);

        Content = rootGrid;
        HeaderOverrideSettings.Changed += OnSettingsChanged;
        Closed += (_, _) => HeaderOverrideSettings.Changed -= OnSettingsChanged;
        RefreshRows();
    }

    private void OnSettingsChanged()
    {
        if (!Dispatcher.CheckAccess())
            Dispatcher.Invoke(RefreshRows);
        else
            RefreshRows();
    }

    public void RefreshRows()
    {
        _rowsList.Children.Clear();
        var items = HeaderOverrideSettings.GetAll();
        if (items.Count == 0)
        {
            _rowsList.Children.Add(new TextBlock
            {
                Text = "No header overrides.",
                Foreground = FgDim,
                FontSize = 11,
                FontStyle = FontStyles.Italic
            });
            return;
        }

        foreach (var item in items)
        {
            var row = new Border
            {
                Background = item.Enabled ? BgItem : BgDark,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(6, 4, 4, 4),
                Margin = new Thickness(0, 0, 0, 3)
            };

            var dock = new DockPanel();
            var snapshot = item;

            var removeBtn = CreateTinyButton("\u2715");
            removeBtn.ToolTip = "Remove";
            removeBtn.Click += (_, _) =>
            {
                var all = HeaderOverrideSettings.GetAll().ToList();
                var idx = all.FindIndex(h => h.Name == snapshot.Name && h.Value == snapshot.Value && h.Enabled == snapshot.Enabled);
                if (idx < 0)
                    idx = all.FindIndex(h => h.Name.Equals(snapshot.Name, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                    all.RemoveAt(idx);
                HeaderOverrideSettings.Replace(all);
                RefreshRows();
                OverridesChanged?.Invoke();
            };
            DockPanel.SetDock(removeBtn, Dock.Right);
            dock.Children.Add(removeBtn);

            var check = new CheckBox
            {
                IsChecked = item.Enabled,
                Foreground = FgText,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = item.Enabled ? "Disable this override" : "Enable this override"
            };
            check.Checked += (_, _) => SetEnabled(snapshot, true);
            check.Unchecked += (_, _) => SetEnabled(snapshot, false);
            DockPanel.SetDock(check, Dock.Left);
            dock.Children.Add(check);

            dock.Children.Add(new TextBlock
            {
                Text = $"{item.Name}: {item.Value}",
                Foreground = item.Enabled ? FgText : FgDim,
                FontSize = 11,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis
            });

            row.Child = dock;
            _rowsList.Children.Add(row);
        }
    }

    private void SetEnabled(HeaderOverride snapshot, bool enabled)
    {
        var all = HeaderOverrideSettings.GetAll().ToList();
        var idx = all.FindIndex(h => h.Name == snapshot.Name && h.Value == snapshot.Value);
        if (idx < 0)
            idx = all.FindIndex(h => h.Name.Equals(snapshot.Name, StringComparison.OrdinalIgnoreCase));
        if (idx < 0) return;
        all[idx].Enabled = enabled;
        HeaderOverrideSettings.Replace(all);
        RefreshRows();
        OverridesChanged?.Invoke();
    }

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var name = _nameBox.Text.Trim();
        if (name.Length == 0) return;

        var all = HeaderOverrideSettings.GetAll().ToList();
        var existing = all.FindIndex(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        var next = new HeaderOverride { Name = name, Value = _valueBox.Text, Enabled = true };
        if (existing >= 0)
            all[existing] = next;
        else
            all.Add(next);
        HeaderOverrideSettings.Replace(all);
        _valueBox.Text = "";
        RefreshRows();
        OverridesChanged?.Invoke();
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        if (HeaderOverrideSettings.GetAll().Count == 0) return;
        if (MessageBox.Show("Remove all header overrides?", "Clear overrides",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        HeaderOverrideSettings.Clear();
        RefreshRows();
        OverridesChanged?.Invoke();
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

    private static TextBox CreateTextBox(string value)
    {
        return new TextBox
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
}
