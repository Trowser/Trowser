using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

namespace Trowser.Pointers;

/// <summary>One rendered pointer, already mapped into overlay-local DIPs by the caller.</summary>
public sealed record PointerMarker(
    int Number,
    string PointerId,
    string Kind,
    string? Caption,
    MapRect LocalRect,
    bool Stale,
    bool OffScreen,
    bool IsAbsence,
    bool Note = false);

/// <summary>
/// P2: the live overlay a human reads when an agent points at things. Modelled on
/// <see cref="Trowser.Api.MessageOverlay"/> — a borderless, transparent, click-through <see cref="Window"/>
/// owned by MainWindow, which is a separate HWND that sits above WebView2's native HWND (WPF child
/// elements cannot, which is the finding that shaped this whole feature).
///
/// It is deliberately dumb: the caller resolves each pointer's current rect, maps it with
/// <see cref="PointerCoordinateMapper"/>, and pushes <see cref="PointerMarker"/>s via
/// <see cref="SetMarkers"/>. Pointers that no longer resolve are shown honestly as parked "stale"
/// chips rather than a confidently-wrong box — an accuracy choice, per the feature's stated goal.
/// </summary>
public sealed class PointerOverlayWindow : Window
{
    private const int GwlExStyle = -20;
    private const int WsExTransparent = 0x00000020;
    private const int WsExLayered = 0x00080000;
    private const int WsExNoActivate = 0x08000000;
    private const int WsExToolWindow = 0x00000080;

    [DllImport("user32.dll")] private static extern int GetWindowLong(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern int SetWindowLong(IntPtr hwnd, int index, int newStyle);

    private readonly FrameworkElement _host;
    private readonly Canvas _canvas;
    private IReadOnlyList<PointerMarker> _markers = Array.Empty<PointerMarker>();

    // Agent accent (matches the "info" accent used elsewhere in the app chrome).
    private static readonly Brush AgentAccent = Freeze("#007ACC");
    private static readonly Brush StaleAccent = Freeze("#888888");
    private static readonly Brush AbsenceAccent = Freeze("#F5A623");
    private static readonly Brush CardBg = Freeze("#1E1E1E");

    public PointerOverlayWindow(Window owner, FrameworkElement host)
    {
        Owner = owner;
        _host = host;

        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Focusable = false;
        ShowActivated = false;
        WindowStartupLocation = WindowStartupLocation.Manual;

        _canvas = new Canvas { ClipToBounds = true };
        Content = _canvas;

        PositionOverHost();
        owner.LocationChanged += OnOwnerChanged;
        owner.SizeChanged += OnOwnerChanged;
        if (host is not null)
            host.SizeChanged += OnOwnerChanged;
    }

    private void OnOwnerChanged(object? sender, EventArgs e)
    {
        PositionOverHost();
        Render();
    }

    /// <summary>Push the current set of mapped markers and redraw.</summary>
    public void SetMarkers(IReadOnlyList<PointerMarker> markers)
    {
        _markers = markers ?? Array.Empty<PointerMarker>();
        Render();
    }

    /// <summary>Cover the WebView host exactly: origin from the control (device px → DIPs), size in DIPs.</summary>
    private void PositionOverHost()
    {
        if (_host is null || !_host.IsVisible) return;
        try
        {
            var originDevice = _host.PointToScreen(new Point(0, 0));
            var dpi = VisualTreeHelper.GetDpi(_host);
            Left = PointerCoordinateMapper.DeviceToDip(originDevice.X, dpi.PixelsPerDip);
            Top = PointerCoordinateMapper.DeviceToDip(originDevice.Y, dpi.PixelsPerDip);
            Width = Math.Max(0, _host.ActualWidth);
            Height = Math.Max(0, _host.ActualHeight);
        }
        catch
        {
            // Host not yet in the visual tree / not connected to a presentation source. Leave as-is.
        }
    }

    private void Render()
    {
        _canvas.Children.Clear();
        // Reserve enough width for the parked note/stale chips (badge + capped text + padding) so they
        // don't run off the right edge either.
        var parkX = Math.Max(8, ActualWidth - 300);
        double parkY = 8;

        foreach (var m in _markers)
        {
            if (m.Note)
            {
                _canvas.Children.Add(MakeNoteChip(m, parkX, parkY));
                parkY += 40;
                continue;
            }

            if (m.OffScreen || m.Stale)
            {
                _canvas.Children.Add(MakeStaleChip(m, parkX, parkY));
                parkY += 34;
                continue;
            }

            AddHighlight(m);
        }
    }

    private void AddHighlight(PointerMarker m)
    {
        var accent = m.IsAbsence ? AbsenceAccent : AgentAccent;
        var r = m.LocalRect;

        var box = new Rectangle
        {
            Width = Math.Max(2, r.Width),
            Height = Math.Max(2, r.Height),
            Stroke = accent,
            StrokeThickness = 2,
            RadiusX = 3,
            RadiusY = 3,
            Fill = Brushes.Transparent,
            IsHitTestVisible = false
        };
        if (m.IsAbsence)
            box.StrokeDashArray = new DoubleCollection { 4, 3 };
        Canvas.SetLeft(box, r.X);
        Canvas.SetTop(box, r.Y);
        _canvas.Children.Add(box);

        var badge = MakeBadge(m.Number, accent);
        Canvas.SetLeft(badge, Math.Max(0, r.X - 2));
        Canvas.SetTop(badge, Math.Max(0, r.Y - 12));
        _canvas.Children.Add(badge);

        if (!string.IsNullOrWhiteSpace(m.Caption))
        {
            var caption = MakeCaption(m.Caption!, accent);

            // Measure so we can keep the whole caption on-screen: clamp to the right edge (the reported
            // bug — captions on right-side elements ran off the window) and flip above the box if it
            // would spill past the bottom.
            caption.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            var cw = caption.DesiredSize.Width;
            var chh = caption.DesiredSize.Height;
            const double margin = 8;

            var cx = r.X;
            if (ActualWidth > 0 && cx + cw > ActualWidth - margin)
                cx = Math.Max(margin, ActualWidth - margin - cw);

            var cy = r.Y + Math.Max(2, r.Height) + 4;
            if (ActualHeight > 0 && cy + chh > ActualHeight - margin)
                cy = Math.Max(margin, r.Y - chh - 4); // flip above the box

            Canvas.SetLeft(caption, cx);
            Canvas.SetTop(caption, cy);
            _canvas.Children.Add(caption);
        }
    }

    private static Border MakeBadge(int number, Brush accent) => new()
    {
        Background = accent,
        CornerRadius = new CornerRadius(10),
        Width = 22,
        Height = 22,
        IsHitTestVisible = false,
        Effect = new DropShadowEffect { Color = Colors.Black, BlurRadius = 6, ShadowDepth = 1, Opacity = 0.6 },
        Child = new TextBlock
        {
            Text = number.ToString(),
            Foreground = Brushes.White,
            FontSize = 12,
            FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Segoe UI"),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        }
    };

    private static Border MakeCaption(string text, Brush accent) => new()
    {
        Background = CardBg,
        BorderBrush = accent,
        BorderThickness = new Thickness(0, 0, 0, 2),
        CornerRadius = new CornerRadius(3),
        Padding = new Thickness(6, 3, 6, 3),
        MaxWidth = 320,
        IsHitTestVisible = false,
        Effect = new DropShadowEffect { Color = Colors.Black, BlurRadius = 8, ShadowDepth = 2, Opacity = 0.6 },
        Child = new TextBlock
        {
            Text = text,
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap
        }
    };

    /// <summary>A parked chip for an anchorless note (a text-only agent handoff, e.g. <c>browser_point</c>
    /// with just a caption). It points at nothing on the page, so it reads as a numbered agent message.</summary>
    private static Border MakeNoteChip(PointerMarker m, double x, double y)
    {
        var badge = MakeBadge(m.Number, AgentAccent);
        var text = new TextBlock
        {
            Text = string.IsNullOrWhiteSpace(m.Caption) ? "(note)" : m.Caption,
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 230,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0)
        };
        var stack = new StackPanel { Orientation = Orientation.Horizontal };
        stack.Children.Add(badge);
        stack.Children.Add(text);

        var chip = new Border
        {
            Background = CardBg,
            BorderBrush = AgentAccent,
            BorderThickness = new Thickness(0, 0, 0, 2),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(8, 5, 10, 5),
            IsHitTestVisible = false,
            Effect = new DropShadowEffect { Color = Colors.Black, BlurRadius = 8, ShadowDepth = 2, Opacity = 0.6 },
            Child = stack
        };
        Canvas.SetLeft(chip, x);
        Canvas.SetTop(chip, y);
        return chip;
    }

    /// <summary>A parked chip for a pointer that no longer resolves or is scrolled off-screen — honest
    /// about not knowing where it is, instead of drawing a box in the wrong place.</summary>
    private static Border MakeStaleChip(PointerMarker m, double x, double y)
    {
        var label = m.OffScreen && !m.Stale ? $"{m.Number}  off-screen" : $"{m.Number}  stale";
        var chip = new Border
        {
            Background = CardBg,
            BorderBrush = StaleAccent,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(11),
            Padding = new Thickness(8, 3, 10, 3),
            IsHitTestVisible = false,
            Opacity = 0.85,
            Child = new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(m.Caption) ? label : $"{label} — {m.Caption}",
                Foreground = StaleAccent,
                FontSize = 11,
                FontFamily = new FontFamily("Segoe UI"),
                MaxWidth = 200,
                TextTrimming = TextTrimming.CharacterEllipsis
            }
        };
        Canvas.SetLeft(chip, x);
        Canvas.SetTop(chip, y);
        return chip;
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        // Click-through + no-activate + tool-window, so the overlay never steals focus or input from
        // the page below. The overlay is passive today; an interactive mode would drop WS_EX_TRANSPARENT.
        var hwnd = new WindowInteropHelper(this).Handle;
        var ex = GetWindowLong(hwnd, GwlExStyle);
        SetWindowLong(hwnd, GwlExStyle, ex | WsExTransparent | WsExLayered | WsExNoActivate | WsExToolWindow);
    }

    protected override void OnContentRendered(EventArgs e)
    {
        base.OnContentRendered(e);
        PositionOverHost();
        Render();
    }

    /// <summary>Detach owner handlers so the overlay can be garbage-collected cleanly.</summary>
    public void Detach()
    {
        if (Owner is Window owner)
        {
            owner.LocationChanged -= OnOwnerChanged;
            owner.SizeChanged -= OnOwnerChanged;
        }
        if (_host is not null)
            _host.SizeChanged -= OnOwnerChanged;
    }

    protected override void OnClosed(EventArgs e)
    {
        Detach();
        base.OnClosed(e);
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
