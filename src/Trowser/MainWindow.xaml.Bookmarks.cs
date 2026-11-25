using System.IO;
using System.Windows;
using Microsoft.Win32;
using Trowser.Api;
using Trowser.Bookmarks;
using Trowser.Repro;
using Trowser.SessionLog;

namespace Trowser;

/// <summary>
/// Bookmarks in the GUI: the nav-bar Catch button and Ctrl+B, plus the Journal panel's Show me,
/// Verify, Go, Export, and Import commands. Logic lives in <see cref="BookmarkService"/>.
/// </summary>
public partial class MainWindow
{
    private void BookmarkButton_Click(object sender, RoutedEventArgs e) => _ = CatchBookmarkFromUiAsync();

    /// <summary>One click, no dialog: write the bookmark and hand focus back to the page.</summary>
    private async Task CatchBookmarkFromUiAsync()
    {
        var service = _automationContext?.BookmarkService;
        if (service == null || !_isWebViewReady)
        {
            StatusText.Text = "Bookmark — browser not ready";
            return;
        }

        try
        {
            var info = await service.CatchAsync("gui");
            var n = info.BookmarkNumber > 0 ? info.BookmarkNumber : info.JournalIndex;
            StatusText.Text = info.Warnings is { Count: > 0 } w
                ? $"Bookmarked \u2014 {Truncate(info.Title, 80)} (bookmark #{n}). {w[0]}"
                : $"Bookmarked \u2014 {Truncate(info.Title, 80)} (bookmark #{n})";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Bookmark failed: {ex.Message}";
            TrowserLog.Warn($"Bookmark catch failed: {ex.Message}");
        }
        finally
        {
            ActiveWebView?.Focus();
        }
    }

    /// <summary>Show me for a bookmark: open the evidence page. No navigation, no replay.</summary>
    private async Task ShowBookmarkEvidenceAsync(SessionLogger.JournalEntry entry)
    {
        var html = JournalReportGenerator.GenerateBookmarkDetailHtml(entry, _sessionLogger.FilePath);
        await OpenHtmlInTabAsync(html, "trowser://bookmark");
        var num = BookmarkInfo.FromEntry(entry).BookmarkNumber;
        StatusText.Text = num > 0 ? $"Show me \u2014 bookmark #{num}" : $"Show me \u2014 bookmark";
    }

    private async Task VerifyBookmarkAsync(SessionLogger.JournalEntry entry)
    {
        var info = BookmarkInfo.FromEntry(entry);
        if (!info.CanVerify)
        {
            StatusText.Text = "Verify \u2014 this bookmark has no replayable steps.";
            return;
        }
        if (_safeMode)
        {
            StatusText.Text = "Verify is disabled in safe mode (replaying steps can change server state).";
            return;
        }
        var service = _automationContext?.BookmarkService;
        if (service == null) return;

        try
        {
            StatusText.Text = "Verify \u2014 replaying bookmark steps\u2026";
            var result = await service.VerifyAsync(entry.Index.ToString(), runs: 1, clearSession: false, source: "gui");
            var verdict = ReproVerifyService.ToApiString(result.Verdict);
            var failure = result.Runs.FirstOrDefault(r => !r.Passed)?.Failure;
            StatusText.Text = failure == null
                ? $"Verify \u2014 {verdict}{(result.Reason != null ? $" ({result.Reason})" : "")}"
                : $"Verify \u2014 {verdict}{(result.Reason != null ? $" ({result.Reason})" : "")}: {Truncate(failure.Message, 120)}";
            JournalPanelControl.Refresh();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Verify failed: {ex.Message}";
            TrowserLog.Warn($"Bookmark verify failed: {ex.Message}");
        }
    }

    /// <summary>Go: restore cookies and storage, navigate, and say plainly that the server is not restored.</summary>
    private async Task GoToBookmarkAsync(SessionLogger.JournalEntry entry)
    {
        var service = _automationContext?.BookmarkService;
        if (service == null) return;
        try
        {
            StatusText.Text = "Restore \u2014 applying cookies and storage\u2026";
            var result = await service.RestoreAsync(entry.Index.ToString(), source: "gui");
            var skipped = result.CookiesSkipped.Count > 0 ? $" Skipped {result.CookiesSkipped.Count} expired cookie(s)." : "";
            StatusText.Text = $"Restore \u2014 {result.Cookies} cookie(s), {result.LocalStorage + result.SessionStorage} storage item(s).{skipped} The server is not restored.";
            JournalPanelControl.Refresh();
        }
        catch (BookmarkException ex)
        {
            StatusText.Text = $"Restore \u2014 {ex.Message}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Restore failed: {ex.Message}";
            TrowserLog.Warn($"Bookmark restore failed: {ex.Message}");
        }
    }

    private void ExportBookmark(SessionLogger.JournalEntry entry)
    {
        var service = _automationContext?.BookmarkService;
        if (service == null) return;
        var info = BookmarkInfo.FromEntry(entry);
        var dlg = new SaveFileDialog
        {
            Filter = "Trowser bookmark (*.zip)|*.zip",
            DefaultExt = ".zip",
            FileName = $"{info.Id}.zip"
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            if (!ExportPathGuard.TryResolve(dlg.FileName, _safeMode, out var full, out var error))
                throw new InvalidOperationException(error ?? "Export path rejected.");
            var result = service.Export(entry.Index.ToString(), full, source: "gui");
            StatusText.Text = result.StateRedacted
                ? $"Bookmark exported to {result.Path} (cookie and storage values redacted)"
                : $"Bookmark exported to {result.Path}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export bookmark failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ImportBookmark()
    {
        var service = _automationContext?.BookmarkService;
        if (service == null) return;
        var dlg = new OpenFileDialog { Filter = "Trowser bookmark (*.zip)|*.zip|All files (*.*)|*.*" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            if (!ExportPathGuard.TryResolveRead(dlg.FileName, out var full, out var error))
                throw new InvalidOperationException(error ?? "Import path rejected.");
            var info = service.ImportOrFind(full, out var alreadyImported);
            StatusText.Text = alreadyImported
                ? $"Bookmark {info.Id} from {Path.GetFileName(full)} was already imported"
                : $"Imported bookmark {info.Id} from {Path.GetFileName(full)}";
            JournalPanelControl.Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import bookmark failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
