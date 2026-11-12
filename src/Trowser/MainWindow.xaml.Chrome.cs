using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Custom window chrome: a single combined title + tab bar (Chrome/Firefox style).
/// The minimize/maximize/close buttons live in the tab strip row; the OS non-client
/// caption is removed via <see cref="System.Windows.Shell.WindowChrome"/> in XAML.
/// </summary>
public partial class MainWindow
{
    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState.Minimized;

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void CloseButton_Click(object sender, RoutedEventArgs e)
        => Close();

    /// <summary>Update the maximize/restore glyph and compensate for the maximize overscan.</summary>
    private void Window_StateChanged(object? sender, EventArgs e)
    {
        // Segoe MDL2 Assets: E922 = maximize, E923 = restore.
        MaximizeButton.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
        MaximizeButton.ToolTip = WindowState == WindowState.Maximized ? "Restore" : "Maximize";

        // When a borderless (WindowChrome) window is maximized, Windows pushes its edges off-screen
        // by the resize-border width to hide the (now invisible) sizing frame. WPF doesn't account
        // for this, so ~8px of our content would be clipped on every side. Pad the root by exactly
        // that amount while maximized so nothing is lost; the padding lands in the off-screen region.
        RootGrid.Margin = WindowState == WindowState.Maximized
            ? GetMaximizedOverscan()
            : new Thickness(0);
    }

    /// <summary>
    /// The per-edge overscan of a maximized borderless window, in device-independent units.
    /// <see cref="SystemParameters.WindowResizeBorderThickness"/> covers the sizing frame but omits
    /// the padded border (SM_CXPADDEDBORDER), so we add it back for a pixel-perfect fit across DPIs.
    /// </summary>
    private Thickness GetMaximizedOverscan()
    {
        var resize = SystemParameters.WindowResizeBorderThickness;
        var dpi = VisualTreeHelper.GetDpi(this);
        var paddedX = GetSystemMetrics(SM_CXPADDEDBORDER) / dpi.DpiScaleX;
        var paddedY = GetSystemMetrics(SM_CXPADDEDBORDER) / dpi.DpiScaleY;

        return new Thickness(
            resize.Left + paddedX,
            resize.Top + paddedY,
            resize.Right + paddedX,
            resize.Bottom + paddedY);
    }

    private const int SM_CXPADDEDBORDER = 92;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);
}
