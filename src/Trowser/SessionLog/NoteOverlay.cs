using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;

namespace Trowser.SessionLog;

/// <summary>
/// A borderless window that lets the tester type a free-form note, bug, enhancement,
/// observation, charter, test idea, testing idea, or user identity. Implemented as a Window
/// (not an in-grid overlay) because WebView2 uses a native HWND that always paints over WPF.
/// Ctrl+Enter saves; Escape dismisses without saving.
/// </summary>
public class NoteOverlay : Window
{
    private readonly ComboBox _kindBox;
    private readonly TextBox _textBox;
    private readonly StackPanel _structuredPanel;
    private readonly TextBox _stepsBox;
    private readonly TextBox _actualBox;
    private readonly TextBox _expectedBox;
    private readonly ComboBox _priorityBox;
    private readonly TextBox _tagsBox;
    private readonly DockPanel _severityRow;
    private readonly ComboBox _severityBox;
    private readonly SessionLogger _logger;
    private readonly Action? _onDismiss;
    private readonly int? _editIndex;
    private bool _dismissed;

    public NoteOverlay(Window owner, SessionLogger logger, Action? onDismiss = null,
        SessionLogger.JournalEntry? edit = null)
    {
        _logger = logger;
        _onDismiss = onDismiss;
        _editIndex = edit?.Index;

        Owner = owner;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        SizeToContent = SizeToContent.WidthAndHeight;
        Topmost = true;

        var card = new Border
        {
            Background = Freeze("#252526"),
            BorderBrush = Freeze("#007ACC"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(20, 16, 20, 16),
            MinWidth = 460,
            MaxWidth = 780,
            Effect = new DropShadowEffect
            {
                Color = Colors.Black,
                BlurRadius = 24,
                ShadowDepth = 4,
                Opacity = 0.6
            }
        };

        var stack = new StackPanel();

        var headerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
        var closeBtn = new TextBlock
        {
            Text = "✕",
            Foreground = Freeze("#888888"),
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = Cursors.Hand,
            ToolTip = "Close (Escape)"
        };
        closeBtn.MouseLeftButtonDown += (_, e) => { e.Handled = true; Dismiss(save: false); };
        closeBtn.MouseEnter += (_, _) => closeBtn.Foreground = Freeze("#D4D4D4");
        closeBtn.MouseLeave += (_, _) => closeBtn.Foreground = Freeze("#888888");
        DockPanel.SetDock(closeBtn, Dock.Right);
        headerRow.Children.Add(closeBtn);
        headerRow.Children.Add(new TextBlock
        {
            Text = edit == null ? "📝 Add a journal entry" : "✏️ Edit journal entry",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        });
        stack.Children.Add(headerRow);

        stack.Children.Add(new TextBlock
        {
            Text = "Ctrl+Enter to save  •  Escape to cancel  •  Markdown: **bold**, lists, `code`",
            Foreground = Freeze("#888888"),
            FontSize = 11,
            Margin = new Thickness(0, 0, 0, 10)
        });

        // Kind picker row
        var kindRow = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
        var kindLabel = new TextBlock
        {
            Text = "Kind:",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            Width = 70,
            VerticalAlignment = VerticalAlignment.Center
        };
        kindRow.Children.Add(kindLabel);
        _kindBox = new ComboBox
        {
            Background = Freeze("#1E1E1E"),
            Foreground = Freeze("#D4D4D4"),
            BorderBrush = Freeze("#3F3F46"),
            FontSize = 13,
            Padding = new Thickness(6, 3, 6, 3)
        };
        DarkComboBoxHelper.ApplyDarkStyle(_kindBox);
        foreach (var kind in NoteKinds.All)
            _kindBox.Items.Add(DarkComboBoxHelper.CreateItem(NoteKinds.DisplayLabel(kind)));
        // Keep Tag on each item for kind lookup
        for (int i = 0; i < NoteKinds.All.Length; i++)
            ((ComboBoxItem)_kindBox.Items[i]).Tag = NoteKinds.All[i];
        _kindBox.SelectedIndex = 0; // "note" first
        _kindBox.SelectionChanged += (_, _) => UpdateStructuredVisibility();
        kindRow.Children.Add(_kindBox);
        stack.Children.Add(kindRow);

        // Main text (title / note body)
        stack.Children.Add(new TextBlock
        {
            Text = "Title / text (first line = title, rest = markdown body):",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 2)
        });
        _textBox = new TextBox
        {
            Background = Freeze("#1E1E1E"),
            Foreground = Freeze("#D4D4D4"),
            CaretBrush = Freeze("#D4D4D4"),
            BorderBrush = Freeze("#3F3F46"),
            BorderThickness = new Thickness(1),
            FontSize = 14,
            FontFamily = new FontFamily("Segoe UI"),
            MinHeight = 60,
            MaxHeight = 120,
            Padding = new Thickness(10, 8, 10, 8),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        _textBox.PreviewKeyDown += TextBox_PreviewKeyDown;
        stack.Children.Add(_textBox);

        // Structured fields (collapsed by default, shown for bug/enhancement)
        _structuredPanel = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };

        _stepsBox = MakeFieldBox("Steps to reproduce:", out var stepsWrap);
        _actualBox = MakeFieldBox("Actual result:", out var actualWrap);
        _expectedBox = MakeFieldBox("Expected result:", out var expectedWrap);

        var priRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        priRow.Children.Add(new TextBlock
        {
            Text = "Priority:",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            Width = 110,
            VerticalAlignment = VerticalAlignment.Center
        });
        _priorityBox = new ComboBox
        {
            Background = Freeze("#1E1E1E"),
            Foreground = Freeze("#D4D4D4"),
            BorderBrush = Freeze("#3F3F46"),
            FontSize = 12,
            Padding = new Thickness(6, 3, 6, 3)
        };
        DarkComboBoxHelper.ApplyDarkStyle(_priorityBox);
        var unsetItem = DarkComboBoxHelper.CreateItem("(unset)");
        unsetItem.Tag = "";
        _priorityBox.Items.Add(unsetItem);
        foreach (var p in new[] { "low", "medium", "high", "critical" })
        {
            var item = DarkComboBoxHelper.CreateItem(p);
            item.Tag = p;
            _priorityBox.Items.Add(item);
        }
        _priorityBox.SelectedIndex = 0;
        priRow.Children.Add(_priorityBox);
        _structuredPanel.Children.Add(priRow);

        _structuredPanel.Children.Add(stepsWrap);
        _structuredPanel.Children.Add(actualWrap);
        _structuredPanel.Children.Add(expectedWrap);

        stack.Children.Add(_structuredPanel);

        _tagsBox = MakeFieldBox("Tags (comma-separated):", out var tagsWrap);
        _tagsBox.AcceptsReturn = false;
        _tagsBox.MinHeight = 28;
        _tagsBox.MaxHeight = 36;
        stack.Children.Add(tagsWrap);

        _severityRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        _severityRow.Children.Add(new TextBlock
        {
            Text = "Severity:",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            Width = 110,
            VerticalAlignment = VerticalAlignment.Center
        });
        _severityBox = new ComboBox
        {
            Background = Freeze("#1E1E1E"),
            Foreground = Freeze("#D4D4D4"),
            BorderBrush = Freeze("#3F3F46"),
            FontSize = 12,
            Padding = new Thickness(6, 3, 6, 3)
        };
        DarkComboBoxHelper.ApplyDarkStyle(_severityBox);
        var sevUnset = DarkComboBoxHelper.CreateItem("(unset)");
        sevUnset.Tag = "";
        _severityBox.Items.Add(sevUnset);
        foreach (var s in NoteKinds.JournalSeverities)
        {
            var item = DarkComboBoxHelper.CreateItem(s);
            item.Tag = s;
            _severityBox.Items.Add(item);
        }
        _severityBox.SelectedIndex = 0;
        _severityRow.Children.Add(_severityBox);
        stack.Children.Add(_severityRow);

        if (edit != null)
            Prefill(edit);
        else
            UpdateStructuredVisibility();

        card.Child = stack;
        Content = card;

        Loaded += (_, _) =>
        {
            _textBox.Focus();
            Keyboard.Focus(_textBox);
        };
    }

    private void UpdateStructuredVisibility()
    {
        var kind = ((_kindBox.SelectedItem as ComboBoxItem)?.Tag as string) ?? NoteKinds.Note;
        bool isStructured = NoteKinds.IsStructured(kind);
        _structuredPanel.Visibility = isStructured ? Visibility.Visible : Visibility.Collapsed;
        _severityRow.Visibility = isStructured ? Visibility.Collapsed : Visibility.Visible;
        if (isStructured)
            CopySeverityIntoPriorityIfUnset();
    }

    /// <summary>
    /// When switching to bug/enhancement, reuse a compatible Severity pick as Priority
    /// so testers who ranked the entry before changing kind do not lose it.
    /// </summary>
    private void CopySeverityIntoPriorityIfUnset()
    {
        var pri = (_priorityBox.SelectedItem as ComboBoxItem)?.Tag as string;
        if (!string.IsNullOrEmpty(pri)) return;
        var sev = (_severityBox.SelectedItem as ComboBoxItem)?.Tag as string;
        if (!NoteKinds.TryNormalizeJournalPriority(sev, out var normalized)) return;
        for (int i = 0; i < _priorityBox.Items.Count; i++)
        {
            if ((_priorityBox.Items[i] as ComboBoxItem)?.Tag as string == normalized)
            {
                _priorityBox.SelectedIndex = i;
                break;
            }
        }
    }

    private TextBox MakeFieldBox(string labelText, out StackPanel wrap)
    {
        wrap = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };
        wrap.Children.Add(new TextBlock
        {
            Text = labelText,
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 2)
        });
        var tb = new TextBox
        {
            Background = Freeze("#1E1E1E"),
            Foreground = Freeze("#D4D4D4"),
            CaretBrush = Freeze("#D4D4D4"),
            BorderBrush = Freeze("#3F3F46"),
            BorderThickness = new Thickness(1),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            MinHeight = 50,
            MaxHeight = 120,
            Padding = new Thickness(8, 6, 8, 6),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        tb.PreviewKeyDown += TextBox_PreviewKeyDown;
        wrap.Children.Add(tb);
        return tb;
    }

    private void TextBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            Dismiss(save: true);
        }
        else if (e.Key == Key.Escape)
        {
            e.Handled = true;
            Dismiss(save: false);
        }
    }

    private void Prefill(SessionLogger.JournalEntry edit)
    {
        for (int i = 0; i < _kindBox.Items.Count; i++)
        {
            if ((_kindBox.Items[i] as ComboBoxItem)?.Tag as string == (edit.Kind ?? edit.Type))
            {
                _kindBox.SelectedIndex = i;
                break;
            }
        }

        var body = edit.Summary ?? "";
        if (!string.IsNullOrEmpty(edit.Details))
            body = body + "\n" + edit.Details;
        _textBox.Text = body;

        if (edit.Fields != null)
        {
            if (edit.Fields.TryGetValue("steps", out var steps)) _stepsBox.Text = steps;
            if (edit.Fields.TryGetValue("actual", out var actual)) _actualBox.Text = actual;
            if (edit.Fields.TryGetValue("expected", out var expected)) _expectedBox.Text = expected;
            if (edit.Fields.TryGetValue("priority", out var pri))
            {
                for (int i = 0; i < _priorityBox.Items.Count; i++)
                {
                    if ((_priorityBox.Items[i] as ComboBoxItem)?.Tag as string == pri)
                    {
                        _priorityBox.SelectedIndex = i;
                        break;
                    }
                }
            }
        }

        if (edit.Tags != null && edit.Tags.Count > 0)
            _tagsBox.Text = string.Join(", ", edit.Tags);

        if (!string.IsNullOrEmpty(edit.Severity))
        {
            for (int i = 0; i < _severityBox.Items.Count; i++)
            {
                if ((_severityBox.Items[i] as ComboBoxItem)?.Tag as string == edit.Severity)
                {
                    _severityBox.SelectedIndex = i;
                    break;
                }
            }
        }

        UpdateStructuredVisibility();
    }

    private void Dismiss(bool save)
    {
        if (_dismissed) return;
        _dismissed = true;

        if (save)
        {
            var kind = ((_kindBox.SelectedItem as ComboBoxItem)?.Tag as string) ?? NoteKinds.Note;
            var raw = _textBox.Text;
            NoteKinds.SplitTitleBody(raw, out var text, out var details);
            bool isStructured = NoteKinds.IsStructured(kind);

            System.Collections.Generic.Dictionary<string, string>? fields = null;
            if (isStructured)
            {
                fields = new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                AddIfPresent(fields, "steps", _stepsBox.Text);
                AddIfPresent(fields, "actual", _actualBox.Text);
                AddIfPresent(fields, "expected", _expectedBox.Text);
                var pri = ((_priorityBox.SelectedItem as ComboBoxItem)?.Tag as string) ?? "";
                AddIfPresent(fields, "priority", pri);
                if (fields.Count == 0) fields = null;
            }

            List<string>? tags = null;
            var tagRaw = _tagsBox.Text;
            if (!string.IsNullOrWhiteSpace(tagRaw))
            {
                tags = tagRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(t => t.ToLowerInvariant())
                    .Where(t => t.Length > 0)
                    .Distinct()
                    .ToList();
                if (tags.Count == 0) tags = null;
            }

            // Bugs/enhancements rank with Priority only; other kinds still use Severity.
            string? severity = null;
            if (!isStructured)
            {
                var sev = ((_severityBox.SelectedItem as ComboBoxItem)?.Tag as string) ?? "";
                severity = string.IsNullOrWhiteSpace(sev) ? null : sev;
            }

            if (!string.IsNullOrEmpty(text) || (fields != null && fields.Count > 0) || _editIndex.HasValue)
            {
                if (string.IsNullOrEmpty(text))
                    text = fields != null && fields.TryGetValue("actual", out var a) ? a : $"(untitled {kind})";

                if (_editIndex.HasValue)
                {
                    _logger.UpdateEntry(_editIndex.Value, kind, text, details, setDetails: true,
                        severity, setSeverity: true, fields, setFields: true, tags, setTags: true);
                }
                else
                {
                    _logger.LogTesterNote(kind, text, severity, fields, tags, details: details);
                }
            }
        }

        _onDismiss?.Invoke();
        Close();
    }

    private static void AddIfPresent(System.Collections.Generic.Dictionary<string, string> dict, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) dict[key] = value.Trim();
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
