using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using Trowser.Security;

namespace Trowser.EndpointProbe;

/// <summary>
/// Modeless results table for Auth Control Identifier probes.
/// </summary>
public class AuthControlResultsDialog : Window
{
    private readonly DataGrid _grid;
    private readonly List<AuthControlIdentifier.ResultRow> _allRows;
    private readonly ComboBox _verdictFilter;
    private readonly TextBlock _summaryBlock;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush FgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");

    /// <summary>Raised when the user wants to open a mutated request in the HTTP Request Editor.</summary>
    public event Action<EndpointProbeItem>? OpenInRequestEditorRequested;

    public AuthControlResultsDialog(Window owner, AuthControlIdentifier.ScanResult result)
    {
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Auth Control Identifier — Results";
        Width = 980;
        Height = 560;
        MinWidth = 700;
        MinHeight = 360;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BgDark;
        _allRows = result.Rows.ToList();

        var root = new DockPanel { Margin = new Thickness(12) };

        var top = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        DockPanel.SetDock(top, Dock.Top);

        top.Children.Add(new TextBlock
        {
            Text = "Auth Control Identifier",
            Foreground = AccentBlue,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        });

        _summaryBlock = new TextBlock
        {
            Text = string.Join("  ·  ", result.Summary),
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6)
        };
        top.Children.Add(_summaryBlock);

        if (result.Consistency.Count > 0)
        {
            var cons = new TextBlock
            {
                Text = "Consistency: " + string.Join("; ", result.Consistency.Select(c => c.Summary)),
                Foreground = FgText,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            };
            top.Children.Add(cons);
        }

        var filterRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
        filterRow.Children.Add(new TextBlock
        {
            Text = "Filter verdict:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        });
        _verdictFilter = CreateFilterComboBox();
        _verdictFilter.SelectionChanged += (_, _) => ApplyFilter();
        filterRow.Children.Add(_verdictFilter);
        top.Children.Add(filterRow);

        root.Children.Add(top);

        var bottom = new DockPanel { Margin = new Thickness(0, 8, 0, 0), LastChildFill = false };
        DockPanel.SetDock(bottom, Dock.Bottom);

        var openBtn = CreateButton("Open mutated in Editor", AccentBlue, width: 180);
        openBtn.Click += OpenSelected_Click;
        DockPanel.SetDock(openBtn, Dock.Left);
        bottom.Children.Add(openBtn);

        var closeBtn = CreateButton("Close", Bc("#3F3F46"), width: 90);
        closeBtn.Click += (_, _) => Close();
        DockPanel.SetDock(closeBtn, Dock.Right);
        bottom.Children.Add(closeBtn);

        root.Children.Add(bottom);

        _grid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            CanUserAddRows = false,
            CanUserDeleteRows = false,
            SelectionMode = DataGridSelectionMode.Single,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            RowBackground = BgDark,
            AlternatingRowBackground = BgMedium,
            HorizontalGridLinesBrush = BorderClr,
            FontSize = 12
        };

        var headerStyle = new Style(typeof(DataGridColumnHeader));
        headerStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgDark));
        headerStyle.Setters.Add(new Setter(Control.BackgroundProperty, Bc("#F3F3F3")));
        headerStyle.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        headerStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 4, 6, 4)));
        headerStyle.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.SemiBold));
        _grid.ColumnHeaderStyle = headerStyle;

        _grid.Columns.Add(TextCol("Method", nameof(AuthControlIdentifier.ResultRow.Method), 70));
        _grid.Columns.Add(TextCol("URL", nameof(AuthControlIdentifier.ResultRow.Url), 220));
        _grid.Columns.Add(TextCol("Kind", nameof(AuthControlIdentifier.ResultRow.Kind), 70));
        _grid.Columns.Add(TextCol("Name", nameof(AuthControlIdentifier.ResultRow.Name), 140));
        _grid.Columns.Add(TextCol("Mutation", nameof(AuthControlIdentifier.ResultRow.Mutation), 70));
        _grid.Columns.Add(TextCol("Baseline", nameof(AuthControlIdentifier.ResultRow.BaselineStatus), 70));
        _grid.Columns.Add(TextCol("Probe", nameof(AuthControlIdentifier.ResultRow.ProbeStatus), 60));
        _grid.Columns.Add(TextCol("Bodies match", nameof(AuthControlIdentifier.ResultRow.BodiesMatch), 90));
        _grid.Columns.Add(TextCol("Verdict", nameof(AuthControlIdentifier.ResultRow.Verdict), 140));
        _grid.Columns.Add(CreateFlagsColumn());

        _grid.MouseDoubleClick += (_, _) => OpenSelected_Click(null!, new RoutedEventArgs());

        root.Children.Add(_grid);
        Content = root;

        ApplyFilter();
    }

    private static DataGridTemplateColumn CreateFlagsColumn()
    {
        var col = new DataGridTemplateColumn
        {
            Header = "Flags",
            Width = new DataGridLength(50)
        };

        var factory = new FrameworkElementFactory(typeof(TextBlock));
        factory.SetBinding(TextBlock.TextProperty, new Binding(nameof(AuthControlIdentifier.ResultRow.FlagWarningIcon)));
        factory.SetValue(TextBlock.ForegroundProperty, Bc("#CCA700"));
        factory.SetValue(TextBlock.FontSizeProperty, 14.0);
        factory.SetValue(TextBlock.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        factory.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        factory.SetBinding(FrameworkElement.ToolTipProperty,
            new Binding(nameof(AuthControlIdentifier.ResultRow.CookieFlagWarning)));

        col.CellTemplate = new DataTemplate { VisualTree = factory };
        return col;
    }

    private ComboBox CreateFilterComboBox()
    {
        var combo = new ComboBox
        {
            Width = 200,
            Background = Bc("#FFFFFF"),
            Foreground = FgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 2, 6, 2),
            FontSize = 11,
            Height = 26
        };

        foreach (var item in new[]
                 {
                     "All", "enforced", "presence-only", "ignored",
                     "value-checked-but-optional", "inconclusive"
                 })
            combo.Items.Add(item);
        combo.SelectedIndex = 0;

        var itemStyle = new Style(typeof(ComboBoxItem));
        itemStyle.Setters.Add(new Setter(Control.BackgroundProperty, Bc("#FFFFFF")));
        itemStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgDark));
        itemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 3, 6, 3)));

        var hover = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
        hover.Setters.Add(new Setter(Control.BackgroundProperty, Bc("#E8E8E8")));
        hover.Setters.Add(new Setter(Control.ForegroundProperty, FgDark));
        itemStyle.Triggers.Add(hover);

        combo.Resources.Add(typeof(ComboBoxItem), itemStyle);
        return combo;
    }

    private void ApplyFilter()
    {
        var filter = _verdictFilter.SelectedItem as string;
        if (string.IsNullOrEmpty(filter) || filter == "All")
            _grid.ItemsSource = _allRows;
        else
            _grid.ItemsSource = _allRows.Where(r => r.Verdict.Equals(filter, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void OpenSelected_Click(object sender, RoutedEventArgs e)
    {
        if (_grid.SelectedItem is not AuthControlIdentifier.ResultRow row)
        {
            MessageBox.Show("Select a result row first.", "Auth Control Identifier",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var item = new EndpointProbeItem
        {
            Method = row.Method,
            Url = row.MutatedUrl,
            RequestHeaders = new Dictionary<string, string>(row.MutatedHeaders, StringComparer.OrdinalIgnoreCase),
            RequestBody = row.MutatedBody
        };
        OpenInRequestEditorRequested?.Invoke(item);
    }

    private static DataGridTextColumn TextCol(string header, string path, double width) => new()
    {
        Header = header,
        Binding = new Binding(path),
        Width = new DataGridLength(width)
    };

    private static Button CreateButton(string text, SolidColorBrush bg, double width) => new()
    {
        Content = text,
        Width = width,
        Height = 28,
        Padding = new Thickness(12, 0, 12, 0),
        Background = bg,
        Foreground = Brushes.White,
        BorderBrush = BorderClr,
        BorderThickness = new Thickness(1),
        FontSize = 12,
        Cursor = System.Windows.Input.Cursors.Hand,
        HorizontalAlignment = HorizontalAlignment.Left,
        Margin = new Thickness(0, 0, 8, 0)
    };

    private static SolidColorBrush Bc(string hex) =>
        (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
}
