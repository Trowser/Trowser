using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Chat;

namespace Trowser;

/// <summary>
/// Edit per-mode AI system prompts. Opened from LLM Settings via "Prompt…".
/// </summary>
public class PromptDialog : Window
{
    private readonly Dictionary<InteractionMode, string?> _overrides;
    private readonly Dictionary<InteractionMode, string> _editors = new();
    private readonly TextBox _promptBox;
    private readonly TextBlock _statusLabel;
    private readonly RadioButton _modeChat;
    private readonly RadioButton _modeFull;
    private readonly RadioButton _modeEconomical;
    private InteractionMode _currentMode;
    private bool _suppressModeChange;

    public string? SystemPromptChat => _overrides[InteractionMode.Chat];
    public string? SystemPromptFull => _overrides[InteractionMode.Full];
    public string? SystemPromptEconomical => _overrides[InteractionMode.Economical];

    /// <summary>Mode last selected in this dialog when OK was clicked.</summary>
    public InteractionMode SelectedMode => _currentMode;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public PromptDialog(Window owner, LlmSettings settings, InteractionMode initialMode = InteractionMode.Economical)
    {
        Owner = owner;
        Title = "AI System Prompts";
        Width = 720;
        Height = 620;
        MinWidth = 560;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;

        _overrides = new Dictionary<InteractionMode, string?>
        {
            [InteractionMode.Chat] = settings.SystemPromptChat,
            [InteractionMode.Full] = settings.SystemPromptFull,
            [InteractionMode.Economical] = settings.SystemPromptEconomical
        };

        foreach (InteractionMode mode in Enum.GetValues<InteractionMode>())
            _editors[mode] = ResolveDisplayText(mode);

        _currentMode = initialMode;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var topStack = new StackPanel { Margin = new Thickness(24, 20, 24, 8) };
        AddSectionHeader(topStack, "System Prompt");
        AddHint(topStack, "Each interaction mode has its own prompt. Changes apply when you click OK in Settings.");

        var modeRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 10, 0, 4) };
        _modeEconomical = CreateModeRadio("Economical", InteractionMode.Economical);
        _modeChat = CreateModeRadio("Chat", InteractionMode.Chat);
        _modeFull = CreateModeRadio("Full", InteractionMode.Full);
        modeRow.Children.Add(_modeEconomical);
        modeRow.Children.Add(_modeChat);
        modeRow.Children.Add(_modeFull);
        topStack.Children.Add(modeRow);

        _statusLabel = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 0)
        };
        topStack.Children.Add(_statusLabel);

        Grid.SetRow(topStack, 0);
        rootGrid.Children.Add(topStack);

        _promptBox = new TextBox
        {
            AcceptsReturn = true,
            AcceptsTab = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10, 8, 10, 8),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas, Cascadia Mono, Courier New"),
            Margin = new Thickness(24, 0, 24, 0),
            VerticalContentAlignment = VerticalAlignment.Top
        };
        _promptBox.TextChanged += (_, _) => UpdateStatusLabel();
        Grid.SetRow(_promptBox, 1);
        rootGrid.Children.Add(_promptBox);

        var actionRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(24, 10, 24, 0)
        };
        var resetBtn = new Button
        {
            Content = "Reset to Default",
            Width = 130,
            Height = 28,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        resetBtn.Click += (_, _) =>
        {
            _promptBox.Text = LlmSystemPrompts.GetDefault(_currentMode);
            _promptBox.CaretIndex = 0;
            UpdateStatusLabel();
        };
        actionRow.Children.Add(resetBtn);
        Grid.SetRow(actionRow, 2);
        rootGrid.Children.Add(actionRow);

        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(24, 12, 24, 16)
        };
        var okButton = CreateButton("OK", true);
        okButton.Click += (_, _) =>
        {
            CommitCurrentEditor();
            DialogResult = true;
        };
        var cancelButton = CreateButton("Cancel", false);
        cancelButton.Click += (_, _) => { DialogResult = false; };
        cancelButton.Margin = new Thickness(8, 0, 0, 0);
        buttonPanel.Children.Add(okButton);
        buttonPanel.Children.Add(cancelButton);
        Grid.SetRow(buttonPanel, 3);
        rootGrid.Children.Add(buttonPanel);

        Content = rootGrid;

        _suppressModeChange = true;
        SelectModeRadio(initialMode);
        _suppressModeChange = false;
        _promptBox.Text = _editors[initialMode];
        UpdateStatusLabel();

        Loaded += (_, _) =>
        {
            _promptBox.Focus();
            _promptBox.CaretIndex = 0;
        };
    }

    private RadioButton CreateModeRadio(string label, InteractionMode mode)
    {
        var rb = new RadioButton
        {
            Content = label,
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 0, 18, 0),
            GroupName = "PromptMode",
            Tag = mode
        };
        rb.Checked += ModeRadio_Checked;
        return rb;
    }

    private void SelectModeRadio(InteractionMode mode)
    {
        _modeChat.IsChecked = mode == InteractionMode.Chat;
        _modeFull.IsChecked = mode == InteractionMode.Full;
        _modeEconomical.IsChecked = mode == InteractionMode.Economical;
    }

    private void ModeRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_suppressModeChange || sender is not RadioButton { IsChecked: true, Tag: InteractionMode mode })
            return;
        if (mode == _currentMode) return;

        CommitCurrentEditor();
        _currentMode = mode;
        _promptBox.Text = _editors[mode];
        _promptBox.CaretIndex = 0;
        UpdateStatusLabel();
    }

    private void CommitCurrentEditor()
    {
        _editors[_currentMode] = _promptBox.Text;
        _overrides[_currentMode] = LlmSystemPrompts.NormalizeOverride(_currentMode, _promptBox.Text);
    }

    private string ResolveDisplayText(InteractionMode mode)
    {
        var custom = _overrides[mode];
        return string.IsNullOrWhiteSpace(custom)
            ? LlmSystemPrompts.GetDefault(mode)
            : custom;
    }

    private void UpdateStatusLabel()
    {
        var normalized = LlmSystemPrompts.NormalizeOverride(_currentMode, _promptBox.Text);
        _statusLabel.Text = normalized == null
            ? "Using built-in default for this mode"
            : "Custom prompt for this mode";
        _statusLabel.Foreground = normalized == null ? FgDim : Bc("#CE9178");
    }

    private static void AddSectionHeader(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = Bc("#569CD6"),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 6)
        });
    }

    private static void AddHint(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap
        });
    }

    private static Button CreateButton(string text, bool isDefault)
    {
        return new Button
        {
            Content = text,
            Width = 90,
            Height = 28,
            IsDefault = isDefault,
            IsCancel = !isDefault,
            Background = isDefault ? Bc("#0E639C") : Bc("#3F3F46"),
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
