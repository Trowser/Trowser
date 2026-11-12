using System.Runtime.InteropServices;
using System.Text;

namespace Trowser;

/// <summary>
/// Detects Chromium DevTools windows that belong to WebView2 browser processes.
/// WebView2 has no API for "is DevTools currently open"; the DevTools UI is a top-level
/// window of the browser process (not Trowser.exe).
/// </summary>
internal static class DevToolsWindowProbe
{
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    internal static bool IsDevToolsTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            return false;

        // Edge/WebView2 uses "DevTools - {url}". Some Chromium builds put "DevTools" at the end.
        return title.Contains("DevTools", StringComparison.OrdinalIgnoreCase)
            || title.StartsWith("Developer Tools", StringComparison.OrdinalIgnoreCase);
    }

    internal static int CountVisible(IEnumerable<uint> processIds)
    {
        var ids = processIds as ISet<uint> ?? processIds.ToHashSet();
        if (ids.Count == 0)
            return 0;

        var count = 0;
        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd))
                return true;

            GetWindowThreadProcessId(hWnd, out var pid);
            if (!ids.Contains(pid))
                return true;

            var sb = new StringBuilder(512);
            if (GetWindowText(hWnd, sb, sb.Capacity) <= 0)
                return true;

            if (IsDevToolsTitle(sb.ToString()))
                count++;

            return true;
        }, IntPtr.Zero);

        return count;
    }

    internal static bool AnyVisible(IEnumerable<uint> processIds) =>
        CountVisible(processIds) > 0;
}
