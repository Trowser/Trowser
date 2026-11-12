using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;

namespace Trowser.Api;

/// <summary>
/// A borderless overlay window that displays a message from an LLM or external tool
/// at the bottom of the Trowser main window. Auto-dismisses after a configurable duration.
/// Implemented as a Window (not an in-grid overlay) because WebView2's native HWND
/// always paints over WPF elements.
/// </summary>
public class MessageOverlay : Window
{
    private readonly DispatcherTimer _timer;
    private bool _dismissed;

    /// <summary>Severity levels that control the accent color of the message.</summary>
    public enum MessageLevel { Info, Warning, Error }

    public MessageOverlay(Window owner, string text, MessageLevel level = MessageLevel.Info, int durationMs = 8000, string? copyText = null)
    {
        Owner = owner;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Focusable = false;
        // Position at bottom of owner
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

        MouseLeftButtonDown += (_, _) => Dismiss();
        KeyDown += (_, e) => { if (e.Key == Key.Escape) Dismiss(); };

        var (accentHex, iconChar) = level switch
        {
            MessageLevel.Warning => ("#F5A623", "!"),
            MessageLevel.Error   => ("#F44747", "✕"),
            _                    => ("#007ACC", "i")
        };

        var card = new Border
        {
            Background = Freeze("#1E1E1E"),
            BorderBrush = Freeze(accentHex),
            BorderThickness = new Thickness(0, 2, 0, 0),
            Padding = new Thickness(16, 10, 16, 10),
            Margin = new Thickness(24, 0, 24, 18),
            CornerRadius = new CornerRadius(6),
            HorizontalAlignment = HorizontalAlignment.Center,
            MaxWidth = 800,
            MinWidth = 300,
            Effect = new DropShadowEffect
            {
                Color = Colors.Black,
                BlurRadius = 20,
                ShadowDepth = 4,
                Opacity = 0.7
            }
        };
        card.MouseLeftButtonDown += (_, e) => e.Handled = true; // don't dismiss when clicking inside card

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        // Icon badge: white text on accent-colored circle
        var iconBadge = new Border
        {
            Background = Freeze(accentHex),
            CornerRadius = new CornerRadius(10),
            Width = 20,
            Height = 20,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 10, 0),
            Child = new TextBlock
            {
                Text = iconChar,
                Foreground = Brushes.White,
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                FontFamily = new FontFamily("Segoe UI"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            }
        };
        Grid.SetColumn(iconBadge, 0);
        grid.Children.Add(iconBadge);

        var textBlock = new TextBlock
        {
            Text = text,
            Foreground = Freeze("#D4D4D4"),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            MaxWidth = 650
        };
        Grid.SetColumn(textBlock, 1);
        grid.Children.Add(textBlock);

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
        var clipboardText = string.IsNullOrWhiteSpace(copyText) ? text : copyText;
        copyBtn.MouseLeftButtonDown += (_, e) =>
        {
            e.Handled = true;
            try { Clipboard.SetText(clipboardText); }
            catch { /* clipboard may be locked */ }
            copyBtn.Text = "✓";
            copyBtn.Foreground = Freeze("#4EC9B0");
        };
        copyBtn.MouseEnter += (_, _) => { if (copyBtn.Text != "✓") copyBtn.Foreground = Freeze("#D4D4D4"); };
        copyBtn.MouseLeave += (_, _) => { if (copyBtn.Text != "✓") copyBtn.Foreground = Freeze("#888888"); };
        Grid.SetColumn(copyBtn, 2);
        grid.Children.Add(copyBtn);

        var closeBtn = new TextBlock
        {
            Text = "✕",
            Foreground = Freeze("#888888"),
            FontSize = 14,
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = Cursors.Hand,
            Margin = new Thickness(8, 0, 0, 0)
        };
        closeBtn.MouseLeftButtonDown += (_, e) => { e.Handled = true; Dismiss(); };
        closeBtn.MouseEnter += (_, _) => closeBtn.Foreground = Freeze("#D4D4D4");
        closeBtn.MouseLeave += (_, _) => closeBtn.Foreground = Freeze("#888888");
        Grid.SetColumn(closeBtn, 3);
        grid.Children.Add(closeBtn);

        card.Child = grid;
        Content = card;

        // Auto-dismiss timer
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(Math.Max(durationMs, 1000)) };
        _timer.Tick += (_, _) => Dismiss();
        _timer.Start();

        // Fade-in animation
        Opacity = 0;
        Loaded += (_, _) =>
        {
            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200));
            BeginAnimation(OpacityProperty, fadeIn);
        };
    }

    private void PositionAtBottom()
    {
        if (Owner is not Window owner) return;

        // Maximized WPF windows report inflated size and negative origin (hidden frame), so
        // Owner.Top + ActualHeight extends past the visible bottom (e.g. into the taskbar).
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

    /// <summary>Dismiss the overlay with a fade-out animation.</summary>
    public void Dismiss()
    {
        if (_dismissed) return;
        _dismissed = true;
        _timer.Stop();

        var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
        fadeOut.Completed += (_, _) => Close();
        BeginAnimation(OpacityProperty, fadeOut);
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        // Reposition after content has been measured so ActualHeight is accurate
        PositionAtBottom();
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
