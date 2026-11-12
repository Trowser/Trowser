using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;

namespace Trowser.Decisions;

/// <summary>
/// Asks for the human's attention when the agent needs a decision, without stealing focus from
/// whatever they are doing. Overlay icon + progress bar stay until the question is resolved;
/// the taskbar flash stops on foreground (noisy while you are in Trowser) and resumes if the
/// window is deactivated while a decision is still pending.
/// </summary>
internal static class AttentionNotifier
{
    private static ImageSource? _amberOverlay;
    private static ImageSource? _urgentOverlay;

    /// <summary>
    /// Flag the window as waiting on the human. Safe to call repeatedly — a second ask while one is
    /// already pending just refreshes the overlay and re-flashes. Must be called on the UI thread.
    /// </summary>
    public static void RequestAttention(Window window, bool urgent, string? description = null)
    {
        ApplyOverlay(window, urgent, description);
        Flash(window, urgent);
    }

    /// <summary>
    /// Keep overlay / progress / description without flashing. Used when refreshing chrome after
    /// an answer that left other decisions pending, or when the window is already in the foreground.
    /// </summary>
    public static void ApplyOverlay(Window window, bool urgent, string? description = null)
    {
        try
        {
            window.TaskbarItemInfo ??= new TaskbarItemInfo();
            // Paused (amber) reads as "stopped, waiting"; Error (red) for an urgent ask. Both need a
            // non-zero value to draw the bar at all.
            window.TaskbarItemInfo.ProgressState = urgent
                ? TaskbarItemProgressState.Error
                : TaskbarItemProgressState.Paused;
            window.TaskbarItemInfo.ProgressValue = 1.0;
            window.TaskbarItemInfo.Description = description ?? "Trowser needs a decision";
            window.TaskbarItemInfo.Overlay = urgent ? UrgentOverlay() : AmberOverlay();
        }
        catch (Exception ex) { TrowserLog.Warn($"Taskbar attention failed: {ex.Message}"); }
    }

    /// <summary>
    /// Flash the taskbar again (e.g. when the user alt-tabs away while a decision is still open).
    /// Does not clear or recreate the overlay.
    /// </summary>
    public static void Reflash(Window window, bool urgent) => Flash(window, urgent);

    /// <summary>Stop the flash only — overlay and progress stay until <see cref="ClearAttention"/>.</summary>
    public static void StopFlashOnly(Window window) => StopFlash(window);

    /// <summary>Clear overlay, progress, and flash once nothing is waiting on the human. Must be called on the UI thread.</summary>
    public static void ClearAttention(Window window)
    {
        try
        {
            if (window.TaskbarItemInfo != null)
            {
                window.TaskbarItemInfo.ProgressState = TaskbarItemProgressState.None;
                window.TaskbarItemInfo.ProgressValue = 0;
                window.TaskbarItemInfo.Description = null;
                window.TaskbarItemInfo.Overlay = null;
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"Taskbar clear failed: {ex.Message}"); }

        StopFlash(window);
    }

    private static ImageSource AmberOverlay() =>
        _amberOverlay ??= BuildOverlay(
            Color.FromRgb(0xF5, 0xA6, 0x23),
            Color.FromRgb(0x1E, 0x1E, 0x1E),
            "?");

    private static ImageSource UrgentOverlay() =>
        _urgentOverlay ??= BuildOverlay(
            Color.FromRgb(0xC7, 0x2E, 0x2E),
            Colors.White,
            "!");

    /// <summary>
    /// 16×16 badge for <see cref="TaskbarItemInfo.Overlay"/> — filled circle with a glyph.
    /// Rendered to a frozen <see cref="RenderTargetBitmap"/> so the shell paints it reliably.
    /// </summary>
    private static ImageSource BuildOverlay(Color fill, Color glyph, string text)
    {
        const int size = 16;
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawEllipse(
                new SolidColorBrush(fill),
                new Pen(new SolidColorBrush(Color.FromArgb(0xCC, 0xFF, 0xFF, 0xFF)), 1.0),
                new Point(size / 2.0, size / 2.0),
                size / 2.0 - 0.5,
                size / 2.0 - 0.5);

            var formatted = new FormattedText(
                text,
                CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
                11,
                new SolidColorBrush(glyph),
                1.0);

            dc.DrawText(formatted, new Point((size - formatted.Width) / 2, (size - formatted.Height) / 2 - 0.5));
        }

        var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(
            size, size, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        bitmap.Freeze();
        return bitmap;
    }

    private static void Flash(Window window, bool urgent)
    {
        var handle = HandleOf(window);
        if (handle == IntPtr.Zero) return;

        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = handle,
            // TIMERNOFG keeps flashing until the human actually brings the window forward.
            // Overlay + progress stay after that — flash alone would vanish on alt-tab back.
            dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount = urgent ? 0u : 5u,
            dwTimeout = 0
        };

        try { FlashWindowEx(ref info); }
        catch (Exception ex) { TrowserLog.Warn($"FlashWindowEx failed: {ex.Message}"); }
    }

    private static void StopFlash(Window window)
    {
        var handle = HandleOf(window);
        if (handle == IntPtr.Zero) return;

        var info = new FLASHWINFO
        {
            cbSize = (uint)Marshal.SizeOf<FLASHWINFO>(),
            hwnd = handle,
            dwFlags = FLASHW_STOP,
            uCount = 0,
            dwTimeout = 0
        };

        try { FlashWindowEx(ref info); }
        catch (Exception ex) { TrowserLog.Warn($"FlashWindowEx stop failed: {ex.Message}"); }
    }

    private static IntPtr HandleOf(Window window)
    {
        try { return new WindowInteropHelper(window).Handle; }
        catch { return IntPtr.Zero; }
    }

    private const uint FLASHW_STOP = 0;
    private const uint FLASHW_ALL = 3;       // caption + taskbar button
    private const uint FLASHW_TIMERNOFG = 12; // flash until the window comes to the foreground

    [StructLayout(LayoutKind.Sequential)]
    private struct FLASHWINFO
    {
        public uint cbSize;
        public IntPtr hwnd;
        public uint dwFlags;
        public uint uCount;
        public uint dwTimeout;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlashWindowEx(ref FLASHWINFO pwfi);
}
