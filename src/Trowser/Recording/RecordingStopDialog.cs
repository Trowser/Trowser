using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Trowser.Recording;

/// <summary>
/// Shown when a recording stops. User picks one or more destinations and an optional description.
/// </summary>
public class RecordingStopDialog : Window
{
    private static readonly SolidColorBrush BgDark = Freeze("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Freeze("#2D2D30");
    private static readonly SolidColorBrush FgText = Freeze("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Freeze("#888888");
    private static readonly SolidColorBrush BorderClr = Freeze("#3F3F46");
    private static readonly SolidColorBrush AccentGreen = Freeze("#16825B");

    private readonly TextBox _descriptionBox;
    private readonly CheckBox _consoleCheck;
    private readonly CheckBox _fileCheck;
    private readonly CheckBox _journalCheck;
    private readonly CheckBox _aiCheck;

    public string Description { get; private set; } = "";
    public bool ToScriptConsole { get; private set; }
    public bool ToFile { get; private set; }
    public bool ToJournal { get; private set; }
    public bool ToAi { get; private set; }

    public RecordingStopDialog(Window owner, string startUrl, IReadOnlyList<string> steps, int actionCount)
    {
        Owner = owner;
        Title = "Recording destinations";
        Width = 520;
        Height = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResize;
        Background = BgMedium;
        ShowInTaskbar = false;

        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var root = new StackPanel { Margin = new Thickness(20, 16, 20, 16) };
        scroll.Content = root;

        root.Children.Add(new TextBlock
        {
            Text = "Save recording",
            Foreground = FgText,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12)
        });

        var preview = new System.Text.StringBuilder();
        preview.AppendLine($"{actionCount} step{(actionCount == 1 ? "" : "s")}");
        if (!string.IsNullOrWhiteSpace(startUrl))
            preview.AppendLine($"Start: {startUrl}");
        var shown = 0;
        foreach (var step in steps)
        {
            if (string.IsNullOrWhiteSpace(step)) continue;
            preview.AppendLine($"- {step}");
            if (++shown >= 6) break;
        }
        if (steps.Count > shown)
            preview.AppendLine($"… and {steps.Count - shown} more");

        root.Children.Add(new Border
        {
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8),
            Margin = new Thickness(0, 0, 0, 12),
            Child = new TextBox
            {
                Text = preview.ToString().TrimEnd(),
                Background = Brushes.Transparent,
                Foreground = FgDim,
                BorderThickness = new Thickness(0),
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 11,
                MaxHeight = 120,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            }
        });

        root.Children.Add(Label("Description (optional):"));
        _descriptionBox = new TextBox
        {
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 12),
            AcceptsReturn = false,
            TextWrapping = TextWrapping.NoWrap
        };
        root.Children.Add(_descriptionBox);

        root.Children.Add(Label("Destinations:"));
        _consoleCheck = DestCheck("Script Console", isChecked: true);
        _fileCheck = DestCheck("File (.csx)", isChecked: false);
        _journalCheck = DestCheck("Journal (Show me can replay)", isChecked: false);
        _aiCheck = DestCheck("Send to AI (prefill chat, do not send)", isChecked: false);
        root.Children.Add(_consoleCheck);
        root.Children.Add(_fileCheck);
        root.Children.Add(_journalCheck);
        root.Children.Add(_aiCheck);

        var btnRow = new DockPanel { Margin = new Thickness(0, 16, 0, 0) };
        var discard = StyledButton("Discard", 100, false);
        discard.Click += (_, _) => { DialogResult = false; Close(); };
        DockPanel.SetDock(discard, Dock.Right);
        btnRow.Children.Add(discard);

        var save = StyledButton("Save", 100, true);
        save.Click += Save_Click;
        DockPanel.SetDock(save, Dock.Right);
        btnRow.Children.Add(save);
        root.Children.Add(btnRow);

        Content = scroll;
        _descriptionBox.Focus();

        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) { DialogResult = false; Close(); }
            else if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control) Save_Click(this, e);
        };
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        ToScriptConsole = _consoleCheck.IsChecked == true;
        ToFile = _fileCheck.IsChecked == true;
        ToJournal = _journalCheck.IsChecked == true;
        ToAi = _aiCheck.IsChecked == true;
        Description = _descriptionBox.Text.Trim();

        if (!ToScriptConsole && !ToFile && !ToJournal && !ToAi)
        {
            MessageBox.Show(this,
                "Pick at least one destination, or click Discard.",
                "Recording destinations",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
        Close();
    }

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = FgText,
        FontSize = 12,
        Margin = new Thickness(0, 0, 0, 4)
    };

    private static CheckBox DestCheck(string text, bool isChecked) => new()
    {
        Content = text,
        IsChecked = isChecked,
        Foreground = FgText,
        FontSize = 12,
        Margin = new Thickness(0, 0, 0, 6)
    };

    private static Button StyledButton(string text, double width, bool primary) => new()
    {
        Content = text,
        Width = width,
        Height = 30,
        FontSize = 12,
        Margin = new Thickness(8, 0, 0, 0),
        Background = primary ? AccentGreen : Freeze("#3E3E42"),
        Foreground = primary ? Brushes.White : FgText,
        BorderBrush = BorderClr,
        BorderThickness = new Thickness(1),
        Cursor = Cursors.Hand
    };

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
