using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Trowser.Security.RaceLab;

namespace Trowser.RaceLab;

internal sealed class RaceLabRequestEditorDialog : Window
{
    private readonly TextBox _nameBox;
    private readonly TextBox _urlBox;
    private readonly ComboBox _methodCombo;
    private readonly ComboBox _sessionCombo;
    private readonly ComboBox _roleCombo;
    private readonly TextBox _bodyBox;
    private readonly TextBox _patternBox;

    public RaceLabRequest Result { get; private set; }

    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FieldBg = Bc("#252526");

    public RaceLabRequestEditorDialog(Window owner, RaceLabRequest seed, IEnumerable<string> peerNames)
    {
        Owner = owner;
        Title = "Race Lab request";
        Width = 640;
        Height = 620;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BgMedium;
        ResizeMode = ResizeMode.CanResizeWithGrip;

        Result = seed.Clone();

        var grid = new Grid { Margin = new Thickness(12) };
        for (var i = 0; i < 7; i++)
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        _nameBox = AddField(grid, 0, "Name", seed.Name);
        _urlBox = AddField(grid, 1, "URL", seed.Url);

        _methodCombo = new ComboBox { Margin = new Thickness(0, 0, 0, 6) };
        foreach (var m in new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD" })
            _methodCombo.Items.Add(m);
        _methodCombo.SelectedItem = string.IsNullOrWhiteSpace(seed.Method) ? "POST" : seed.Method.ToUpperInvariant();
        AddLabeled(grid, 2, "Method", _methodCombo);

        _sessionCombo = new ComboBox { Margin = new Thickness(0, 0, 0, 6) };
        foreach (var s in RaceLabSessions.BuiltInOptions)
            _sessionCombo.Items.Add(s);
        foreach (var peer in peerNames.Distinct(StringComparer.OrdinalIgnoreCase))
            _sessionCombo.Items.Add(peer);
        _sessionCombo.SelectedItem = RaceLabSessions.Normalize(seed.Session);
        AddLabeled(grid, 3, "Session", _sessionCombo);

        _roleCombo = new ComboBox { Margin = new Thickness(0, 0, 0, 6) };
        foreach (var r in RaceLabRoles.All)
            _roleCombo.Items.Add(r);
        _roleCombo.SelectedItem = RaceLabRoles.Normalize(seed.Role);
        AddLabeled(grid, 4, "Role", _roleCombo);

        _patternBox = AddField(grid, 5, "Response pattern (regex)", seed.ResponsePattern ?? "");

        grid.Children.Add(new TextBlock
        {
            Text = "Body",
            Foreground = FgText,
            Margin = new Thickness(0, 4, 0, 4)
        });
        Grid.SetRow(grid.Children[^1], 6);

        _bodyBox = new TextBox
        {
            Text = seed.Body ?? "",
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = FieldBg,
            Foreground = FgText,
            FontFamily = new FontFamily("Consolas"),
            MinHeight = 80
        };
        Grid.SetRow(_bodyBox, 7);
        grid.Children.Add(_bodyBox);

        var hint = new TextBlock
        {
            Text = "Role: observe = monitor only (no duplicate-action race finding). mutate = single-use / state change. check = TOCTOU validation. Optional response pattern: .NET regex against the response body (empty = skip).",
            Foreground = Bc("#888888"),
            TextWrapping = TextWrapping.Wrap,
            FontSize = 11,
            Margin = new Thickness(0, 8, 0, 0)
        };
        Grid.SetRow(hint, 8);
        grid.Children.Add(hint);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };
        var ok = new Button { Content = "OK", Width = 80, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
        ok.Click += (_, _) =>
        {
            if (!TryBuildResult(out var err))
            {
                MessageBox.Show(this, err, "Race Lab", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DialogResult = true;
            Close();
        };
        var cancel = new Button { Content = "Cancel", Width = 80, IsCancel = true };
        cancel.Click += (_, _) => { DialogResult = false; Close(); };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        Grid.SetRow(buttons, 9);
        grid.Children.Add(buttons);

        Content = grid;
    }

    private bool TryBuildResult(out string error)
    {
        error = "";
        var url = _urlBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(url))
        {
            error = "URL is required.";
            return false;
        }

        Result = new RaceLabRequest
        {
            Name = _nameBox.Text.Trim(),
            Url = url,
            Method = (_methodCombo.SelectedItem as string ?? "POST").ToUpperInvariant(),
            Session = (_sessionCombo.SelectedItem as string ?? RaceLabSessions.AllPeers).Trim(),
            Role = RaceLabRoles.Normalize(_roleCombo.SelectedItem as string),
            Body = string.IsNullOrWhiteSpace(_bodyBox.Text) ? null : _bodyBox.Text,
            ResponsePattern = string.IsNullOrWhiteSpace(_patternBox.Text) ? null : _patternBox.Text.Trim()
        };
        if (string.IsNullOrWhiteSpace(Result.Name))
            Result.Name = $"{Result.Method} {Result.Url}";
        return true;
    }

    private static TextBox AddField(Grid grid, int row, string label, string value)
    {
        var tb = new TextBox
        {
            Text = value,
            Margin = new Thickness(0, 0, 0, 6),
            Background = FieldBg,
            Foreground = FgText
        };
        AddLabeled(grid, row, label, tb);
        return tb;
    }

    private static void AddLabeled(Grid grid, int row, string label, Control control)
    {
        var sp = new StackPanel();
        sp.Children.Add(new TextBlock { Text = label, Foreground = FgText, Margin = new Thickness(0, 0, 0, 2) });
        sp.Children.Add(control);
        Grid.SetRow(sp, row);
        grid.Children.Add(sp);
    }

    private static SolidColorBrush Bc(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex));
}
