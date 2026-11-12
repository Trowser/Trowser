using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace Trowser;

/// <summary>
/// Win32 monitor work area in coordinates compatible with WPF <see cref="Window.Left"/> / <see cref="Window.Top"/> (DIPs).
/// </summary>
internal static class WindowMonitorBounds
{
    private const uint MonitorDefaultToNearest = 2;

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    /// <summary>
    /// Work area of the monitor containing the window (excludes taskbar), in WPF device-independent pixels.
    /// </summary>
    public static Rect GetMonitorWorkAreaDips(Window window)
    {
        var hwnd = new WindowInteropHelper(window).EnsureHandle();
        var hMonitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        var mi = new MONITORINFO { cbSize = Marshal.SizeOf(typeof(MONITORINFO)) };
        if (hMonitor == IntPtr.Zero || !GetMonitorInfo(hMonitor, ref mi))
            return SystemParameters.WorkArea;

        var dpi = VisualTreeHelper.GetDpi(window);
        var pxToDip = 1.0 / dpi.PixelsPerDip;

        return new Rect(
            mi.rcWork.Left * pxToDip,
            mi.rcWork.Top * pxToDip,
            (mi.rcWork.Right - mi.rcWork.Left) * pxToDip,
            (mi.rcWork.Bottom - mi.rcWork.Top) * pxToDip);
    }
}
