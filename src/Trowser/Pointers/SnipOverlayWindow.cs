using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Trowser.Pointers;

/// <summary>
/// The result of a snip: a rectangle in the frozen bitmap's pixel space, a caption, and
/// whether the tester marked it as an absence ("something should be here and isn't").
/// </summary>
public sealed class SnipResult
{
    public Rect BitmapRect { get; init; }
    public string? Caption { get; init; }
    public bool IsAbsence { get; init; }

    /// <summary>False when the tester sent a text-only handoff (no rectangle drawn) — common when a
    /// screenshot isn't the point. There is then no region/crop to anchor, just the caption.</summary>
    public bool HasRegion { get; init; }
}

/// <summary>
/// Snip-style rectangle drawer for the <c>!?</c> handoff (P1). Displays a frozen bitmap of the
/// page (captured the instant <c>!?</c> was pressed — this "freezes the moment" for free) over a
/// dark scrim and lets the tester drag a rectangle, click a point, or mark an absence, then add a
/// caption. All coordinates are resolved against the frozen bitmap's pixel space, so the mapping
/// back to page CSS pixels is exact and DPI-independent (no screen-coordinate guesswork).
///
/// Implemented as a borderless transparent <see cref="Window"/> owned by MainWindow because
/// WebView2's native HWND paints over in-tree WPF elements (same reason as MessageOverlay).
/// </summary>
public sealed class SnipOverlayWindow : Window
{
    private readonly BitmapSource _bitmap;
    private readonly Image _image;
    private readonly Canvas _canvas;
    private readonly TextBox _captionBox;
    private readonly CheckBox _absenceBox;

    private Rectangle? _rubberBand;
    private Point _dragStart;
    private bool _dragging;
    private Rect _selectionDisplay; // selection in canvas/display coordinates

    /// <summary>Set when the tester confirms; null when cancelled.</summary>
    public SnipResult? Result { get; private set; }

    public SnipOverlayWindow(Window owner, BitmapSource frozenPage)
    {
        _bitmap = frozenPage;

        Owner = owner;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = new SolidColorBrush(Color.FromArgb(0xCC, 0x10, 0x10, 0x10));
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Topmost = true;
        WindowStartupLocation = WindowStartupLocation.Manual;

        PositionOverOwner(owner);

        var root = new DockPanel { LastChildFill = true };

        // ---- Bottom toolbar ----
        var toolbar = new Border
        {
            Background = Freeze("#1E1E1E"),
            BorderBrush = Freeze("#007ACC"),
            BorderThickness = new Thickness(0, 2, 0, 0),
            Padding = new Thickness(14, 8, 14, 8)
        };
        DockPanel.SetDock(toolbar, Dock.Bottom);

        var bar = new DockPanel { LastChildFill = true };

        var hint = new TextBlock
        {
            Text = "Drag a box (or click) around what you want to point at — or just type a note and Send. Enter to send · Esc to cancel.",
            Foreground = Freeze("#9A9A9A"),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0)
        };
        DockPanel.SetDock(hint, Dock.Top);

        _absenceBox = new CheckBox
        {
            Content = "Nothing here (absence)",
            Foreground = Freeze("#D4D4D4"),
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 12, 0),
            ToolTip = "Mark that something should be in this box but isn't."
        };
        DockPanel.SetDock(_absenceBox, Dock.Left);

        var sendBtn = MakeButton("Send", "#007ACC");
        sendBtn.Click += (_, _) => Confirm();
        DockPanel.SetDock(sendBtn, Dock.Right);

        var cancelBtn = MakeButton("Cancel", "#3A3A3A");
        cancelBtn.Click += (_, _) => Cancel();
        DockPanel.SetDock(cancelBtn, Dock.Right);

        _captionBox = new TextBox
        {
            Background = Freeze("#2D2D2D"),
            Foreground = Freeze("#EDEDED"),
            BorderBrush = Freeze("#3F3F3F"),
            BorderThickness = new Thickness(1),
            CaretBrush = Brushes.White,
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Padding = new Thickness(6, 4, 6, 4),
            VerticalContentAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
            MinWidth = 240
        };
        _captionBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) { Confirm(); e.Handled = true; }
        };

        var captionRow = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 6, 0, 0) };
        DockPanel.SetDock(_absenceBox, Dock.Left);
        DockPanel.SetDock(cancelBtn, Dock.Right);
        DockPanel.SetDock(sendBtn, Dock.Right);
        captionRow.Children.Add(_absenceBox);
        captionRow.Children.Add(cancelBtn);
        captionRow.Children.Add(sendBtn);
        captionRow.Children.Add(_captionBox); // fills remaining space

        var toolbarStack = new StackPanel();
        toolbarStack.Children.Add(hint);
        toolbarStack.Children.Add(captionRow);
        toolbar.Child = toolbarStack;

        // ---- Frozen image + drawing canvas ----
        var stage = new Grid { Margin = new Thickness(16) };
        _image = new Image
        {
            Source = _bitmap,
            Stretch = Stretch.Uniform,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            SnapsToDevicePixels = true
        };
        _canvas = new Canvas { Background = Brushes.Transparent, Cursor = Cursors.Cross };
        _canvas.MouseLeftButtonDown += Canvas_MouseLeftButtonDown;
        _canvas.MouseMove += Canvas_MouseMove;
        _canvas.MouseLeftButtonUp += Canvas_MouseLeftButtonUp;
        stage.Children.Add(_image);
        stage.Children.Add(_canvas);

        root.Children.Add(toolbar);
        root.Children.Add(stage);
        Content = root;

        KeyDown += (_, e) => { if (e.Key == Key.Escape) { Cancel(); e.Handled = true; } };
        Loaded += (_, _) => _canvas.Focus();
    }

    private void PositionOverOwner(Window owner)
    {
        if (owner.WindowState == WindowState.Maximized)
        {
            var wa = WindowMonitorBounds.GetMonitorWorkAreaDips(owner);
            Left = wa.Left; Top = wa.Top; Width = wa.Width; Height = wa.Height;
        }
        else
        {
            Left = owner.Left; Top = owner.Top;
            Width = owner.ActualWidth; Height = owner.ActualHeight;
        }
    }

    // ----- Drawing -----

    private void Canvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        _dragStart = ClampToImage(e.GetPosition(_canvas));
        _dragging = true;
        _canvas.CaptureMouse();

        _rubberBand ??= CreateRubberBand();
        if (!_canvas.Children.Contains(_rubberBand))
            _canvas.Children.Add(_rubberBand);
        UpdateRubberBand(_dragStart, _dragStart);
    }

    private void Canvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_dragging) return;
        UpdateRubberBand(_dragStart, ClampToImage(e.GetPosition(_canvas)));
    }

    private void Canvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_dragging) return;
        _dragging = false;
        _canvas.ReleaseMouseCapture();

        var end = ClampToImage(e.GetPosition(_canvas));
        var rect = new Rect(_dragStart, end);

        // A click (no meaningful drag) becomes a small point box around the click.
        if (rect.Width < 6 && rect.Height < 6)
        {
            const double half = 14;
            rect = new Rect(end.X - half, end.Y - half, half * 2, half * 2);
            rect = Rect.Intersect(rect, DisplayedImageRect());
            UpdateRubberBand(rect.TopLeft, rect.BottomRight);
        }

        _selectionDisplay = rect;
        _captionBox.Focus();
    }

    private Rectangle CreateRubberBand() => new()
    {
        Stroke = Freeze("#4EC9F0"),
        StrokeThickness = 2,
        Fill = new SolidColorBrush(Color.FromArgb(0x33, 0x4E, 0xC9, 0xF0)),
        StrokeDashArray = new DoubleCollection { 4, 2 }
    };

    private void UpdateRubberBand(Point a, Point b)
    {
        if (_rubberBand == null) return;
        var x = Math.Min(a.X, b.X);
        var y = Math.Min(a.Y, b.Y);
        _rubberBand.Width = Math.Abs(a.X - b.X);
        _rubberBand.Height = Math.Abs(a.Y - b.Y);
        Canvas.SetLeft(_rubberBand, x);
        Canvas.SetTop(_rubberBand, y);
    }

    private Point ClampToImage(Point p)
    {
        var r = DisplayedImageRect();
        return new Point(
            Math.Max(r.Left, Math.Min(r.Right, p.X)),
            Math.Max(r.Top, Math.Min(r.Bottom, p.Y)));
    }

    /// <summary>The rectangle the Uniform-stretched image actually occupies inside the canvas.</summary>
    private Rect DisplayedImageRect() =>
        Fit(_canvas.ActualWidth, _canvas.ActualHeight, _bitmap.PixelWidth, _bitmap.PixelHeight);

    private static Rect Fit(double cw, double ch, double iw, double ih)
    {
        if (iw <= 0 || ih <= 0 || cw <= 0 || ch <= 0) return new Rect(0, 0, Math.Max(cw, 0), Math.Max(ch, 0));
        var scale = Math.Min(cw / iw, ch / ih);
        var w = iw * scale;
        var h = ih * scale;
        return new Rect((cw - w) / 2, (ch - h) / 2, w, h);
    }

    // ----- Confirm / cancel -----

    private void Confirm()
    {
        var caption = string.IsNullOrWhiteSpace(_captionBox.Text) ? null : _captionBox.Text.Trim();
        var noRegion = _selectionDisplay.Width < 2 || _selectionDisplay.Height < 2;

        if (noRegion)
        {
            // No box drawn. If the tester typed something, send it as a text-only handoff (the common
            // case when a screenshot isn't the point). If they've drawn nothing and typed nothing,
            // nudge rather than sending an empty pointer.
            if (caption == null && _absenceBox.IsChecked != true)
            {
                _captionBox.Focus();
                return;
            }

            Result = new SnipResult { Caption = caption, IsAbsence = _absenceBox.IsChecked == true, HasRegion = false };
            try { DialogResult = true; } catch { /* not shown modally */ }
            Close();
            return;
        }

        var disp = DisplayedImageRect();
        if (disp.Width <= 0 || disp.Height <= 0) { Cancel(); return; }

        // Map display rect → normalized [0,1] within the image → bitmap pixels.
        var sx = _bitmap.PixelWidth / disp.Width;
        var sy = _bitmap.PixelHeight / disp.Height;
        var bx = (_selectionDisplay.X - disp.X) * sx;
        var by = (_selectionDisplay.Y - disp.Y) * sy;
        var bw = _selectionDisplay.Width * sx;
        var bh = _selectionDisplay.Height * sy;

        var bitmapRect = new Rect(
            Math.Max(0, bx),
            Math.Max(0, by),
            Math.Min(_bitmap.PixelWidth, bw),
            Math.Min(_bitmap.PixelHeight, bh));

        Result = new SnipResult
        {
            BitmapRect = bitmapRect,
            Caption = caption,
            IsAbsence = _absenceBox.IsChecked == true,
            HasRegion = true
        };
        try { DialogResult = true; } catch { /* not shown modally */ }
        Close();
    }

    private void Cancel()
    {
        Result = null;
        try { DialogResult = false; } catch { /* not shown modally */ }
        Close();
    }

    private static Button MakeButton(string text, string bgHex)
    {
        var b = new Button
        {
            Content = text,
            Padding = new Thickness(14, 5, 14, 5),
            Margin = new Thickness(6, 0, 0, 0),
            Background = Freeze(bgHex),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Cursor = Cursors.Hand
        };
        return b;
    }

    private static SolidColorBrush Freeze(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
