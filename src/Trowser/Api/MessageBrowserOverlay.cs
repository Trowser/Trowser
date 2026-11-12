using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using static Trowser.MainWindow;

namespace Trowser.Api;

/// <summary>
/// A browsable overlay that lets the user navigate through all received API messages.
/// Opened from the status bar message icon. Stays open until explicitly closed.
/// </summary>
public class MessageBrowserOverlay : Window
{
    private readonly IReadOnlyList<StoredMessage> _messages;
    private int _currentIndex;

    private readonly TextBlock _textBlock;
    private readonly TextBlock _counterText;
    private readonly TextBlock _timestampText;
    private readonly Border _iconBadge;
    private readonly TextBlock _iconChar;
    private readonly Border _leftArrow;
    private readonly Border _rightArrow;
    private readonly Border _card;

    public MessageBrowserOverlay(Window owner, IReadOnlyList<StoredMessage> messages)
    {
        if (messages.Count == 0) throw new ArgumentException("No messages to display.");

        Owner = owner;
        _messages = messages;
        _currentIndex = messages.Count - 1; // start at most recent

        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Focusable = true;
        WindowStartupLocation = WindowStartupLocation.Manual;
        Width = owner.ActualWidth;
        SizeToContent = SizeToContent.Height;

        PositionAtBottom();
        owner.LocationChanged += (_, _) => PositionAtBottom();
        owner.SizeChanged += (_, _) =>
        {
            Width = owner.ActualWidth;
            PositionAtBottom();
        };

        MouseLeftButtonDown += (_, _) => Close();
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) Close();
            else if (e.Key == Key.Left) Navigate(-1);
            else if (e.Key == Key.Right) Navigate(1);
        };

        // Build UI
        _card = new Border
        {
            Background = Freeze("#1E1E1E"),
            BorderBrush = Freeze("#007ACC"),
            BorderThickness = new Thickness(0, 2, 0, 0),
            Padding = new Thickness(16, 10, 16, 10),
            Margin = new Thickness(24, 0, 24, 18),
            CornerRadius = new CornerRadius(6),
            HorizontalAlignment = HorizontalAlignment.Center,
            MaxWidth = 800,
            MinWidth = 520,
            Effect = new DropShadowEffect
            {
                Color = Colors.Black,
                BlurRadius = 20,
                ShadowDepth = 4,
                Opacity = 0.7
            }
        };
        _card.MouseLeftButtonDown += (_, e) => e.Handled = true;

        var outerStack = new DockPanel();

        // Top row: navigation + counter + timestamp + close
        var topRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };

        _leftArrow = MakeArrowButton("◀", -1);
        DockPanel.SetDock(_leftArrow, Dock.Left);
        topRow.Children.Add(_leftArrow);

        var closeBtn = new TextBlock
        {
            Text = "✕",
            Foreground = Freeze("#888888"),
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = Cursors.Hand,
            Margin = new Thickness(8, 0, 0, 0)
        };
        closeBtn.MouseLeftButtonDown += (_, e) => { e.Handled = true; Close(); };
        closeBtn.MouseEnter += (_, _) => closeBtn.Foreground = Freeze("#D4D4D4");
        closeBtn.MouseLeave += (_, _) => closeBtn.Foreground = Freeze("#888888");
        DockPanel.SetDock(closeBtn, Dock.Right);
        topRow.Children.Add(closeBtn);

        _rightArrow = MakeArrowButton("▶", 1);
        DockPanel.SetDock(_rightArrow, Dock.Right);
        topRow.Children.Add(_rightArrow);

        // Counter and timestamp in center
        var centerInfo = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };

        _counterText = new TextBlock
        {
            Foreground = Freeze("#888888"),
            FontSize = 11,
            FontFamily = new FontFamily("Segoe UI"),
            VerticalAlignment = VerticalAlignment.Center
        };
        centerInfo.Children.Add(_counterText);

        _timestampText = new TextBlock
        {
            Foreground = Freeze("#666666"),
            FontSize = 11,
            FontFamily = new FontFamily("Segoe UI"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(10, 0, 0, 0)
        };
        centerInfo.Children.Add(_timestampText);

        topRow.Children.Add(centerInfo);

        DockPanel.SetDock(topRow, Dock.Top);
        outerStack.Children.Add(topRow);

        // Message content row: icon + text + copy
        var contentGrid = new Grid();
        contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        contentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _iconBadge = new Border
        {
            CornerRadius = new CornerRadius(10),
            Width = 20,
            Height = 20,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 10, 0)
        };
        _iconChar = new TextBlock
        {
            Foreground = Brushes.White,
            FontSize = 12,
            FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Segoe UI"),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };
        _iconBadge.Child = _iconChar;
        Grid.SetColumn(_iconBadge, 0);
        contentGrid.Children.Add(_iconBadge);

        _textBlock = new TextBlock
        {
            Foreground = Freeze("#D4D4D4"),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            MaxWidth = 650
        };
        Grid.SetColumn(_textBlock, 1);
        contentGrid.Children.Add(_textBlock);

        var copyBtn = new TextBlock
        {
            Text = "📋",
            Foreground = Freeze("#888888"),
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = Cursors.Hand,
            Margin = new Thickness(10, 0, 0, 0),
            ToolTip = "Copy message (includes extra details when available)"
        };
        copyBtn.MouseLeftButtonDown += (_, e) =>
        {
            e.Handled = true;
            try { Clipboard.SetText(_messages[_currentIndex].TextToCopy); }
            catch { /* clipboard may be locked */ }
            copyBtn.Text = "✓";
            copyBtn.Foreground = Freeze("#4EC9B0");
        };
        copyBtn.MouseEnter += (_, _) => { if (copyBtn.Text != "✓") copyBtn.Foreground = Freeze("#D4D4D4"); };
        copyBtn.MouseLeave += (_, _) => { if (copyBtn.Text != "✓") copyBtn.Foreground = Freeze("#888888"); };
        Grid.SetColumn(copyBtn, 2);
        contentGrid.Children.Add(copyBtn);

        outerStack.Children.Add(contentGrid);
        _card.Child = outerStack;
        Content = _card;

        UpdateDisplay();

        // Fade-in
        Opacity = 0;
        Loaded += (_, _) =>
        {
            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200));
            BeginAnimation(OpacityProperty, fadeIn);
        };
    }

    private void Navigate(int direction)
    {
        var newIndex = _currentIndex + direction;
        if (newIndex < 0 || newIndex >= _messages.Count) return;
        _currentIndex = newIndex;
        UpdateDisplay();
    }

    private void UpdateDisplay()
    {
        var msg = _messages[_currentIndex];

        _textBlock.Text = msg.Text;
        _counterText.Text = $"{_currentIndex + 1} / {_messages.Count}";
        _timestampText.Text = msg.Timestamp.ToString("HH:mm:ss");

        var (accentHex, iconText) = msg.Level switch
        {
            "warning" => ("#F5A623", "!"),
            "error" => ("#F44747", "✕"),
            _ => ("#007ACC", "i")
        };

        _iconBadge.Background = Freeze(accentHex);
        _iconChar.Text = iconText;
        _card.BorderBrush = Freeze(accentHex);

        _leftArrow.Visibility = _currentIndex > 0 ? Visibility.Visible : Visibility.Hidden;
        _rightArrow.Visibility = _currentIndex < _messages.Count - 1 ? Visibility.Visible : Visibility.Hidden;
    }

    private Border MakeArrowButton(string arrow, int direction)
    {
        var text = new TextBlock
        {
            Text = arrow,
            Foreground = Freeze("#888888"),
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Center
        };

        var border = new Border
        {
            Background = Freeze("#2D2D2D"),
            CornerRadius = new CornerRadius(3),
            Padding = new Thickness(8, 2, 8, 2),
            Margin = new Thickness(direction < 0 ? 0 : 4, 0, direction > 0 ? 0 : 4, 0),
            Cursor = Cursors.Hand,
            Child = text
        };

        border.MouseLeftButtonDown += (_, e) => { e.Handled = true; Navigate(direction); };
        border.MouseEnter += (_, _) =>
        {
            border.Background = Freeze("#3E3E3E");
            text.Foreground = Freeze("#D4D4D4");
        };
        border.MouseLeave += (_, _) =>
        {
            border.Background = Freeze("#2D2D2D");
            text.Foreground = Freeze("#888888");
        };

        return border;
    }

    private void PositionAtBottom()
    {
        if (Owner is not Window owner) return;

        if (owner.WindowState == WindowState.Maximized)
        {
            var wa = WindowMonitorBounds.GetMonitorWorkAreaDips(owner);
            Left = wa.Left;
            Width = wa.Width;
            Top = wa.Bottom - ActualHeight - 8;
            return;
        }

        Left = owner.Left;
        Width = owner.ActualWidth;
        Top = owner.Top + owner.ActualHeight - ActualHeight - 8;
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        PositionAtBottom();
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
