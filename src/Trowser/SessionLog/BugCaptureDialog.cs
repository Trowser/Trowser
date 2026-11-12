using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Trowser.SessionLog;

/// <summary>
/// "Add to bug" dialog opened from the page right-click menu. Pre-filled with evidence
/// captured at the moment of the right-click — the clicked element, current URL, a screenshot,
/// recent repro steps (from the narration buffer), and recent console/network errors — so the
/// tester only has to type what was wrong. Saves a structured <see cref="NoteKinds.Bug"/>
/// entry to the journal.
/// </summary>
public class BugCaptureDialog : Window
{
    private static readonly SolidColorBrush BgDark = Freeze("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Freeze("#2D2D30");
    private static readonly SolidColorBrush FgText = Freeze("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Freeze("#888888");
    private static readonly SolidColorBrush BorderClr = Freeze("#3F3F46");
    private static readonly SolidColorBrush AccentGreen = Freeze("#16825B");

    private readonly TextBox _titleBox;
    private readonly TextBox _actualBox;
    private readonly TextBox _expectedBox;
    private readonly TextBox _stepsBox;
    private readonly ComboBox _priorityBox;

    private readonly string? _screenshotPath;
    private readonly string _evidenceNotes;

    /// <summary>Bug title (Summary). Valid after the dialog returns true. Named to avoid hiding <see cref="Window.Title"/>.</summary>
    public string BugTitle { get; private set; } = "";

    public BugCaptureDialog(Window owner, string elementDescription, string? url,
        string prefilledSteps, string? screenshotPath, string evidenceNotes)
    {
        _screenshotPath = screenshotPath;
        _evidenceNotes = evidenceNotes;

        Owner = owner;
        Title = "Add bug";
        Width = 560;
        Height = 620;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResize;
        Background = BgMedium;
        ShowInTaskbar = false;

        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var root = new StackPanel { Margin = new Thickness(20, 16, 20, 16) };
        scroll.Content = root;

        root.Children.Add(new TextBlock
        {
            Text = "Add bug",
            Foreground = FgText,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12)
        });

        // Evidence summary (read-only)
        var evidence = new System.Text.StringBuilder();
        if (!string.IsNullOrWhiteSpace(elementDescription)) evidence.AppendLine($"Element: {elementDescription}");
        if (!string.IsNullOrWhiteSpace(url)) evidence.AppendLine($"URL: {url}");
        if (!string.IsNullOrWhiteSpace(screenshotPath)) evidence.AppendLine($"Screenshot: {screenshotPath}");
        if (!string.IsNullOrWhiteSpace(evidenceNotes)) evidence.AppendLine(evidenceNotes);

        var evidenceText = evidence.ToString().TrimEnd();
        if (!string.IsNullOrEmpty(evidenceText))
        {
            root.Children.Add(Label("Auto-captured evidence:"));
            root.Children.Add(new Border
            {
                Background = BgDark,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8),
                Margin = new Thickness(0, 0, 0, 12),
                Child = new TextBox
                {
                    Text = evidenceText,
                    Background = Brushes.Transparent,
                    Foreground = FgDim,
                    BorderThickness = new Thickness(0),
                    IsReadOnly = true,
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 11,
                    MaxHeight = 110,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                }
            });
        }

        root.Children.Add(Label("Title:"));
        _titleBox = InputBox(1);
        root.Children.Add(_titleBox);

        root.Children.Add(Label("What went wrong (actual):"));
        _actualBox = InputBox(3);
        root.Children.Add(_actualBox);

        root.Children.Add(Label("Expected (optional):"));
        _expectedBox = InputBox(2);
        root.Children.Add(_expectedBox);

        root.Children.Add(Label("Steps to reproduce:"));
        _stepsBox = InputBox(5);
        _stepsBox.Text = prefilledSteps ?? "";
        root.Children.Add(_stepsBox);

        root.Children.Add(Label("Priority:"));
        _priorityBox = new ComboBox { Width = 160, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 12) };
        foreach (var p in new[] { "(none)", "low", "medium", "high", "critical" })
            _priorityBox.Items.Add(new ComboBoxItem { Content = p, Tag = p });
        _priorityBox.SelectedIndex = 0;
        root.Children.Add(_priorityBox);

        // Buttons
        var btnRow = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        var cancel = StyledButton("Cancel", 100, false);
        cancel.Click += (_, _) => { DialogResult = false; Close(); };
        DockPanel.SetDock(cancel, Dock.Right);
        btnRow.Children.Add(cancel);

        var save = StyledButton("Add bug", 120, true);
        save.Click += Save_Click;
        DockPanel.SetDock(save, Dock.Right);
        btnRow.Children.Add(save);
        root.Children.Add(btnRow);

        Content = scroll;

        _actualBox.Focus();
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) { DialogResult = false; Close(); }
            else if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control) Save_Click(this, e);
        };
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var title = _titleBox.Text.Trim();
        var actual = _actualBox.Text.Trim();

        if (string.IsNullOrEmpty(title) && string.IsNullOrEmpty(actual))
        {
            MessageBox.Show(this, "Please enter a title or describe what went wrong.", "Add bug",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Synthesize a title from the actual text when the tester didn't type one.
        if (string.IsNullOrEmpty(title))
        {
            title = actual.Replace("\r", " ").Replace("\n", " ").Trim();
            if (title.Length > 100) title = title[..97] + "...";
        }

        BugTitle = title;

        DialogResult = true;
        Close();
    }

    /// <summary>Build the structured journal fields for the bug. Valid after the dialog returns true.</summary>
    public Dictionary<string, string> BuildFields()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var steps = _stepsBox.Text.Trim();
        if (!string.IsNullOrEmpty(steps)) fields["steps"] = steps;

        var actual = _actualBox.Text.Trim();
        if (!string.IsNullOrEmpty(actual)) fields["actual"] = actual;

        var expected = _expectedBox.Text.Trim();
        if (!string.IsNullOrEmpty(expected)) fields["expected"] = expected;

        var priority = (_priorityBox.SelectedItem as ComboBoxItem)?.Tag as string;
        if (priority is not (null or "(none)")) fields["priority"] = priority;

        if (!string.IsNullOrWhiteSpace(_screenshotPath)) fields["screenshot"] = _screenshotPath!;

        if (!string.IsNullOrWhiteSpace(_evidenceNotes)) fields["notes"] = _evidenceNotes.Trim();

        return fields;
    }

    // --- UI helpers ---

    private static TextBlock Label(string text) => new()
    {
        Text = text,
        Foreground = FgText,
        FontSize = 12,
        Margin = new Thickness(0, 0, 0, 4)
    };

    private static TextBox InputBox(int lines) => new()
    {
        Background = BgDark,
        Foreground = FgText,
        CaretBrush = FgText,
        BorderBrush = BorderClr,
        BorderThickness = new Thickness(1),
        Padding = new Thickness(6, 4, 6, 4),
        FontSize = 12,
        Margin = new Thickness(0, 0, 0, 12),
        AcceptsReturn = lines > 1,
        TextWrapping = lines > 1 ? TextWrapping.Wrap : TextWrapping.NoWrap,
        MinLines = lines,
        MaxLines = Math.Max(lines, 8),
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto
    };

    private static Button StyledButton(string text, double width, bool primary)
    {
        return new Button
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
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
