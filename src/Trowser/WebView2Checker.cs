using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace Trowser;

/// <summary>
/// Diagnoses WebView2 Runtime availability and architecture mismatches.
/// Shows a user-friendly dialog with specific fix instructions when initialization fails.
/// </summary>
internal static class WebView2Checker
{
    private const string WebView2RuntimeGuid = "{F3017226-FE2A-4295-8BEB-E15AB5810CD5}";
    private const string EdgeDownloadUrl = "https://www.microsoft.com/edge";
    private const string WebView2DownloadUrl = "https://developer.microsoft.com/en-us/microsoft-edge/webview2/";

    /// <summary>
    /// Analyzes the system to determine why WebView2 initialization failed,
    /// shows an appropriate dialog, and offers to open the download page.
    /// Returns a short status string for the status bar.
    /// </summary>
    public static string HandleFailure(Exception ex, string? browserExeFolder = null)
    {
        var hasX64Runtime = HasRegistryVersion(@"SOFTWARE\Microsoft\EdgeUpdate\Clients\" + WebView2RuntimeGuid);
        var hasX86Runtime = HasRegistryVersion(@"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\" + WebView2RuntimeGuid);
        var hasX64Edge = File.Exists(@"C:\Program Files\Microsoft\Edge\Application\msedge.exe");
        var hasX86Edge = File.Exists(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
        var hasX64WebView = Directory.Exists(@"C:\Program Files\Microsoft\EdgeWebView");
        var hasX86WebView = Directory.Exists(@"C:\Program Files (x86)\Microsoft\EdgeWebView");

        bool hasAnyX86 = hasX86Runtime || hasX86Edge || hasX86WebView;
        bool hasAnyX64 = hasX64Runtime || hasX64Edge || hasX64WebView;

        // Diagnostic info for the bundled runtime
        var diagLines = new System.Collections.Generic.List<string>();
        diagLines.Add($"Exception: {ex.Message}");
        diagLines.Add($"ProcessPath: {Environment.ProcessPath}");
        diagLines.Add($"browserExeFolder: {browserExeFolder ?? "(null — using system runtime)"}");
        if (browserExeFolder != null)
        {
            diagLines.Add($"Folder exists: {Directory.Exists(browserExeFolder)}");
            var msedgeWv2 = Path.Combine(browserExeFolder, "msedgewebview2.exe");
            diagLines.Add($"msedgewebview2.exe exists: {File.Exists(msedgeWv2)}");
        }
        var diagnostic = string.Join("\n", diagLines);

        string message;
        string downloadUrl;

        if (hasAnyX86 && !hasAnyX64)
        {
            message =
                "Trowser is a 64-bit application, but only 32-bit (x86) Microsoft Edge / WebView2 was found on this system.\n\n" +
                "To fix this:\n" +
                "1. Download 64-bit Microsoft Edge from microsoft.com/edge\n" +
                "2. Install it (this upgrades your existing Edge)\n" +
                "3. Restart Trowser\n\n" +
                $"--- Diagnostic ---\n{diagnostic}\n\n" +
                "Would you like to open the download page now?";
            downloadUrl = EdgeDownloadUrl;
        }
        else if (!hasAnyX86 && !hasAnyX64)
        {
            message =
                "The WebView2 Runtime is not installed on this system.\n\n" +
                "Trowser requires the WebView2 Runtime (included with Microsoft Edge).\n\n" +
                "To fix this:\n" +
                "1. Download the WebView2 Evergreen Runtime (x64)\n" +
                "2. Install it\n" +
                "3. Restart Trowser\n\n" +
                $"--- Diagnostic ---\n{diagnostic}\n\n" +
                "Would you like to open the download page now?";
            downloadUrl = WebView2DownloadUrl;
        }
        else if (ex.Message.Contains("already in use by another Trowser instance", StringComparison.OrdinalIgnoreCase)
                 || ex.Message.Contains("already in use by another Trowser", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(
                ex.Message + "\n\n" +
                "Each named session can only be open in one Trowser window at a time.\n" +
                "Close the other window or pick a different --session name.",
                "Trowser — Session Already Open",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            return "Session already in use — see dialog for details";
        }
        else
        {
            message =
                $"WebView2 failed to initialize unexpectedly.\n\n" +
                $"Error: {ex.Message}\n\n" +
                $"64-bit Edge/WebView2 appears to be installed, so this may be a permissions or configuration issue. " +
                $"Try reinstalling Microsoft Edge (64-bit).\n\n" +
                $"--- Diagnostic ---\n{diagnostic}\n\n" +
                "Would you like to open the Edge download page now?";
            downloadUrl = EdgeDownloadUrl;
        }

        var result = MessageBox.Show(
            message,
            "Trowser — Browser Engine Not Available",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            try
            {
                Process.Start(new ProcessStartInfo(downloadUrl) { UseShellExecute = true });
            }
            catch
            {
                // Fall through — if we can't open a browser, there's not much we can do
            }
        }

        return "WebView2 not available — see error dialog for details";
    }

    /// <summary>
    /// Produces a diagnostic summary for CLI output (no UI dialogs).
    /// </summary>
    public static string GetCliDiagnostic(Exception ex)
    {
        var hasX64Runtime = HasRegistryVersion(@"SOFTWARE\Microsoft\EdgeUpdate\Clients\" + WebView2RuntimeGuid);
        var hasX86Runtime = HasRegistryVersion(@"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\" + WebView2RuntimeGuid);
        var hasX64Edge = File.Exists(@"C:\Program Files\Microsoft\Edge\Application\msedge.exe");
        var hasX86Edge = File.Exists(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");

        bool hasAnyX86 = hasX86Runtime || hasX86Edge;
        bool hasAnyX64 = hasX64Runtime || hasX64Edge;

        if (hasAnyX86 && !hasAnyX64)
        {
            return $"[Error] Failed to initialize WebView2: only 32-bit (x86) Edge/WebView2 found.\n" +
                   $"  Trowser requires 64-bit Edge. Install from: {EdgeDownloadUrl}";
        }

        if (!hasAnyX86 && !hasAnyX64)
        {
            return $"[Error] Failed to initialize WebView2: runtime not installed.\n" +
                   $"  Download from: {WebView2DownloadUrl}";
        }

        return $"[Error] Failed to initialize WebView2: {ex.Message}\n" +
               $"  Try reinstalling 64-bit Edge from: {EdgeDownloadUrl}";
    }

    private static bool HasRegistryVersion(string subKey)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey);
            var value = key?.GetValue("pv") as string;
            return !string.IsNullOrEmpty(value) && value != "0.0.0.0";
        }
        catch
        {
            return false;
        }
    }
}
