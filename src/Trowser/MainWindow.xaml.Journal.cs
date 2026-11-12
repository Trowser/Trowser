using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Trowser.Pointers;
using Trowser.Recording;
using Trowser.Scripting;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region Journal panel (Pillar 4)

    private DispatcherTimer? _coverageDebounce;

    /// <summary>Wire the left-docked Journal panel to the session logger and coverage lens.</summary>
    private void InitializeJournalPanel()
    {
        JournalPanelControl.Initialize(_sessionLogger, () => _automationContext?.ActiveTab?.Url, _sessionMemory);
        JournalPanelControl.SessionLogRequested += OpenSessionLogDialog;
        JournalPanelControl.RecordToggleRequested += ToggleJournalRecording;
        JournalPanelControl.CloseRequested += () => IsJournalPanelVisible = false;
        JournalPanelControl.ReportRequested += () => _ = OpenJournalReportInTabAsync();
        JournalPanelControl.DetailRequested += uri => _ = OpenJournalDetailAsync(uri);

        _coverageDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _coverageDebounce.Tick += (_, _) => { _coverageDebounce!.Stop(); UpdateCoverageSummary(); };

        // Keep the coverage line fresh as the journal grows (debounced; only when panel is visible).
        _sessionLogger.JournalChanged += () =>
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (!IsJournalPanelVisible) return;
                _coverageDebounce!.Stop();
                _coverageDebounce.Start();
            }, DispatcherPriority.Background);
        };
    }

    private void JournalToggleMenu_Click(object sender, RoutedEventArgs e) => IsJournalPanelVisible = !IsJournalPanelVisible;

    /// <summary>
    /// Finish showing the Journal panel: optionally start session logging (so the journal is
    /// captured, not just displayed), ensure the embedded WebView2 exists, and refresh content.
    /// Pass <paramref name="autoStartLogging"/> only for a user opening the panel — restoring
    /// a previously visible panel must respect the persisted Start/Stop preference.
    /// </summary>
    private async Task ShowJournalPanelAsync(bool autoStartLogging = true)
    {
        try
        {
            if (autoStartLogging)
                EnsureSessionLoggingStarted(force: true);
            if (_webView2Environment != null)
                await JournalPanelControl.EnsureWebViewAsync(_webView2Environment);
            JournalPanelControl.Refresh();
            UpdateCoverageSummary();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Show journal panel failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Resume session logging on startup when the user last left it on.
    /// </summary>
    private void RestoreSessionLoggingIfEnabled()
    {
        if (_sessionLogSettings.LoggingEnabled)
            EnsureSessionLoggingStarted();
        JournalPanelControl.UpdateRecordingState();
    }

    private void ToggleJournalRecording()
    {
        if (_sessionLogger.IsLogging)
        {
            _sessionLogger.Stop();
            _sessionLogSettings.LoggingEnabled = false;
            _sessionLogSettings.Save();
        }
        else
        {
            EnsureSessionLoggingStarted(force: true);
        }
        UpdateLogStatusDisplay();
        JournalPanelControl.UpdateRecordingState();
    }

    /// <summary>
    /// Start session logging to a sensible default file if it isn't already running.
    /// When <paramref name="force"/> is true (user opened the Journal panel), this opts in
    /// and persists <see cref="SessionLogSettings.LoggingEnabled"/>. Restore/startup paths
    /// must not force — they honor the saved preference.
    /// </summary>
    private void EnsureSessionLoggingStarted(bool force = false)
    {
        if (_sessionLogger.IsLogging) return;
        if (!force && !_sessionLogSettings.LoggingEnabled) return;

        try
        {
            var path = _sessionLogSettings.LogFilePath;
            if (string.IsNullOrWhiteSpace(path))
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Trowser Sessions");
                Directory.CreateDirectory(dir);
                path = Path.Combine(dir, $"session-{DateTime.Now:yyyyMMdd_HHmmss}.md");
                _sessionLogSettings.LogFilePath = path;
            }

            _sessionLogger.Start(path, _automationContext?.ActiveTab?.Url);
            _sessionLogSettings.LoggingEnabled = true;
            _sessionLogSettings.Save();
            UpdateLogStatusDisplay();
            JournalPanelControl.UpdateRecordingState();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Auto-start session logging failed: {ex.Message}");
        }
    }

    private void UpdateCoverageSummary()
    {
        try
        {
            var snapshot = _coverageService.Build(_sessionLogger.GetJournal(), _automationContext?.ActiveTab?.Url);
            JournalPanelControl.SetCoverageSummary(snapshot.ToSummaryLine(), snapshot.ToTooltip());
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Coverage summary update failed: {ex.Message}");
        }
    }

    private async Task OpenJournalReportInTabAsync()
    {
        if (_automationContext == null || !_isWebViewReady) return;
        try
        {
            var entries = _sessionLogger.GetJournal();
            var html = JournalReportGenerator.GenerateHtml(entries, _sessionLogger.FilePath, _automationContext.ActiveTab?.Url);
            await OpenHtmlInTabAsync(html, "trowser://journal-report");
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Open journal report failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Handle a click on a clickable Journal-panel item. The panel emits pseudo-URLs
    /// (<c>trowser://recording/{index}</c>, <c>trowser://apiactions</c>) which we render to a full
    /// detail page and open in a new browser tab (main use case: copy details into a bug report).
    /// </summary>
    private async Task OpenJournalDetailAsync(string uri)
    {
        if (_automationContext == null || !_isWebViewReady) return;
        try
        {
            var entries = _sessionLogger.GetJournal();

            if (uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                StatusText.Text = uri;
                await _automationContext.Navigate(uri);
                return;
            }

            if (uri.StartsWith("trowser://edit/", StringComparison.OrdinalIgnoreCase))
            {
                var idPart = uri["trowser://edit/".Length..].TrimEnd('/');
                if (!int.TryParse(idPart, out var index)) return;
                var entry = _sessionLogger.GetEntry(index);
                if (entry == null) return;
                ShowNoteOverlay(entry);
                return;
            }

            if (uri.StartsWith("trowser://delete/", StringComparison.OrdinalIgnoreCase))
            {
                var idPart = uri["trowser://delete/".Length..].TrimEnd('/');
                if (!int.TryParse(idPart, out var index)) return;
                var entry = _sessionLogger.GetEntry(index);
                if (entry == null) return;
                var preview = string.IsNullOrWhiteSpace(entry.Summary) ? $"#{index}" : Truncate(entry.Summary, 80);
                var result = MessageBox.Show(
                    $"Delete journal entry #{index}?\n\n{preview}",
                    "Delete journal entry",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                    _sessionLogger.DeleteEntry(index);
                return;
            }

            if (uri.StartsWith("trowser://show/", StringComparison.OrdinalIgnoreCase))
            {
                var idPart = uri["trowser://show/".Length..].TrimEnd('/');
                if (!int.TryParse(idPart, out var index)) return;
                await ShowJournalEntryAsync(index);
                return;
            }

            if (uri.StartsWith("trowser://copy/", StringComparison.OrdinalIgnoreCase))
            {
                var idPart = uri["trowser://copy/".Length..].TrimEnd('/');
                if (!int.TryParse(idPart, out var index)) return;
                CopyJournalEntry(index);
                return;
            }

            if (uri.Equals("trowser://save", StringComparison.OrdinalIgnoreCase))
            {
                SaveJournalJson();
                return;
            }

            if (uri.Equals("trowser://open", StringComparison.OrdinalIgnoreCase))
            {
                OpenJournalJson();
                return;
            }

            if (uri.StartsWith("trowser://recording/", StringComparison.OrdinalIgnoreCase))
            {
                var idPart = uri["trowser://recording/".Length..].TrimEnd('/');
                if (!int.TryParse(idPart, out var index)) return;
                var entry = entries.FirstOrDefault(e => e.Index == index);
                if (entry == null) return;
                var html = JournalReportGenerator.GenerateRecordingDetailHtml(entry);
                await OpenHtmlInTabAsync(html, "trowser://recording");
            }
            else if (uri.StartsWith("trowser://apiactions", StringComparison.OrdinalIgnoreCase))
            {
                var html = JournalReportGenerator.GenerateActionsDetailHtml(entries);
                await OpenHtmlInTabAsync(html, "trowser://api-actions");
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Open journal detail failed: {ex.Message}");
        }
    }

    private async Task ShowJournalEntryAsync(int index)
    {
        var entry = _sessionLogger.GetEntry(index);
        if (entry == null)
        {
            StatusText.Text = $"Journal entry #{index} is gone.";
            return;
        }

        if (!string.IsNullOrWhiteSpace(entry.Url) && _automationContext != null)
        {
            var current = "";
            try { current = await _automationContext.GetCurrentUrl(); } catch { /* best effort */ }
            if (!string.Equals(current, entry.Url, StringComparison.OrdinalIgnoreCase))
            {
                StatusText.Text = $"Show me — navigating to {entry.Url}";
                await _automationContext.Navigate(entry.Url);
            }
        }

        var pointerIds = new List<string>();
        if (entry.Fields != null && entry.Fields.TryGetValue("pointerId", out var pid) && !string.IsNullOrWhiteSpace(pid))
            pointerIds.Add(pid);
        if (string.Equals(entry.Type, "pointer", StringComparison.OrdinalIgnoreCase)
            && pointerIds.Count == 0
            && entry.Fields != null
            && entry.Fields.TryGetValue("pointerId", out var standalone)
            && !string.IsNullOrWhiteSpace(standalone))
            pointerIds.Add(standalone);

        if (pointerIds.Count > 0)
        {
            var first = _pointerStore.Get(pointerIds[0]);
            if (first?.Anchors.Rect != null && _automationContext != null)
            {
                var r = first.Anchors.Rect;
                var ci = System.Globalization.CultureInfo.InvariantCulture;
                try
                {
                    await _automationContext.ExecuteJs(
                        $"window.scrollTo({r.ScrollX.ToString(ci)}, {r.ScrollY.ToString(ci)})");
                }
                catch { /* best effort */ }
            }
            ShowSpecificPointers(pointerIds);
        }

        var reproPath = entry.Fields != null && entry.Fields.TryGetValue("trwPath", out var tp) ? tp
            : entry.Fields != null && entry.Fields.TryGetValue("reproPath", out var rp) ? rp : null;
        if (!string.IsNullOrWhiteSpace(reproPath) && _apiServer != null)
        {
            try
            {
                var body = JsonBodyFromObject(new { trwPath = reproPath, runs = 1, clearSession = false, safetyMode = "active" });
                await _apiServer.BuildReproVerifyAsync(body);
                StatusText.Text = "Show me — repro ran";
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"Show me repro failed: {ex.Message}");
                StatusText.Text = $"Show me — pointers displayed; repro failed: {ex.Message}";
            }
            return;
        }

        string? csx = null;
        if (entry.Fields != null && entry.Fields.TryGetValue("csx", out var embedded) && !string.IsNullOrWhiteSpace(embedded))
            csx = embedded;
        else if (entry.Fields != null && entry.Fields.TryGetValue("csxPath", out var csxPath)
                 && !string.IsNullOrWhiteSpace(csxPath) && File.Exists(csxPath))
        {
            try { csx = await File.ReadAllTextAsync(csxPath); }
            catch (Exception ex) { TrowserLog.Warn($"Show me read csxPath failed: {ex.Message}"); }
        }

        if (!string.IsNullOrWhiteSpace(csx))
        {
            await RunJournalRecordingScriptAsync(csx!);
            return;
        }

        StatusText.Text = pointerIds.Count > 0
            ? $"Show me — {pointerIds.Count} pointer(s) on the page"
            : "Show me — navigated to the entry URL";
    }

    /// <summary>Replay an embedded recording .csx from Journal Show me (same engine as ▶ Play).</summary>
    private async Task RunJournalRecordingScriptAsync(string code)
    {
        if (_scriptEngine == null || _automationContext == null)
        {
            StatusText.Text = "Show me — script engine not ready";
            return;
        }

        if (_playRun != null || _scriptConsoleRun != null)
        {
            StatusText.Text = "Show me — another script is already running";
            return;
        }

        _playRun = new ScriptRunControl();
        _automationContext.ScriptRunControl = _playRun;
        SetPlayRunUiRunning();
        ClearOutput();
        LogToOutput("[Show me] Recording");
        StatusText.Text = "Show me — running recording\u2026";
        _automationContext.Assert.Reset();

        try
        {
            await RunCsxScriptFileAsync("recording", code, _playRun);
            if (!StatusText.Text.Contains("failed", StringComparison.OrdinalIgnoreCase)
                && !StatusText.Text.Contains("cancelled", StringComparison.OrdinalIgnoreCase))
                StatusText.Text = "Show me — recording ran";
        }
        catch (Exception ex)
        {
            LogColoredToOutput($"[Error] {ex.Message}", "#F44747");
            StatusText.Text = $"Show me — recording failed: {ex.Message}";
        }
        finally
        {
            _automationContext.ScriptRunControl = null;
            _playRun.Dispose();
            _playRun = null;
            _playRunStatusText = null;
            SetPlayRunUiIdle();
        }
    }

    private void CopyJournalEntry(int index)
    {
        var entry = _sessionLogger.GetEntry(index);
        if (entry == null) return;
        var json = JsonSerializer.Serialize(JournalProjection.ProjectEntry(entry), new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        Clipboard.SetText(json);
        StatusText.Text = $"Copied journal entry #{index}";
    }

    private void SaveJournalJson()
    {
        var dlg = new SaveFileDialog
        {
            Filter = "Trowser journal (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json",
            FileName = $"journal-{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var json = JournalBundle.Serialize(_sessionLogger.GetJournal(), _pointerStore);
            File.WriteAllText(dlg.FileName, json);
            StatusText.Text = $"Journal saved to {dlg.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save journal failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OpenJournalJson()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Trowser journal (*.json)|*.json|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var imported = ImportJournalJson(File.ReadAllText(dlg.FileName));
            StatusText.Text = $"Imported {imported} journal entries from {Path.GetFileName(dlg.FileName)}";
            JournalPanelControl.Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Open journal failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private int ImportJournalJson(string json)
    {
        var bundle = JournalBundle.Deserialize(json);
        var idMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (bundle.Pointers != null)
        {
            foreach (var dto in bundle.Pointers)
            {
                var pointer = dto.ToPointer();
                if (!string.IsNullOrEmpty(pointer.Id) && _pointerStore.Get(pointer.Id) != null)
                    pointer.Id = "";
                var stored = _pointerStore.Add(pointer);
                if (!string.IsNullOrEmpty(dto.Id) && dto.Id != stored.Id)
                    idMap[dto.Id] = stored.Id;
            }
        }

        var count = 0;
        foreach (var dto in bundle.Entries)
        {
            var entry = dto.ToEntry();
            if (entry.Fields != null && entry.Fields.TryGetValue("pointerId", out var oldId)
                && idMap.TryGetValue(oldId, out var newId))
                entry.Fields["pointerId"] = newId;
            _sessionLogger.ImportEntry(entry);
            count++;
        }
        return count;
    }

    private static Trowser.Api.JsonBody JsonBodyFromObject(object value)
    {
        var json = JsonSerializer.Serialize(value);
        using var doc = JsonDocument.Parse(json);
        return Trowser.Api.JsonBody.FromToolArguments(doc.RootElement);
    }

    /// <summary>Open self-contained HTML in a browser tab, reusing an existing tab with the same display URL.</summary>
    private async Task OpenHtmlInTabAsync(string html, string displayUrl)
    {
        html = HtmlExportText.PrepareDocument(html);
        var existing = _automationContext!.Tabs.FirstOrDefault(t =>
            string.Equals(t.DisplayUrlOverride, displayUrl, StringComparison.OrdinalIgnoreCase));
        if (existing != null)
        {
            var idx = _automationContext.Tabs.ToList().IndexOf(existing);
            if (idx >= 0) _automationContext.SwitchTab(idx);
            existing.WebView.CoreWebView2?.NavigateToString(html);
            return;
        }

        await _automationContext.NewTab(null);
        if (_automationContext.ActiveTab != null)
            _automationContext.ActiveTab.DisplayUrlOverride = displayUrl;
        ActiveWebView?.CoreWebView2?.NavigateToString(html);
    }

    #endregion

    #region Narration buffer (Pillar 3)

    private readonly List<string> _recentNarration = new();
    private const int MaxNarrationEntries = 40;

    // Full step list for the recording in progress (uncapped), used to log one journal entry per
    // recording when it stops. Distinct from _recentNarration, which is a rolling window for "Add to bug".
    private readonly List<string> _currentRecordingSteps = new();
    private string _currentRecordingLabel = "Recording";
    private string? _currentRecordingUrl;

    /// <summary>Begin collecting steps for a new recording (called from StartRecording).</summary>
    private void BeginRecordingCapture(string label, string? startUrl)
    {
        lock (_currentRecordingSteps)
        {
            _currentRecordingSteps.Clear();
            _currentRecordingLabel = string.IsNullOrWhiteSpace(label) ? "Recording" : label;
            _currentRecordingUrl = startUrl;
        }
    }

    /// <summary>
    /// Flush the collected steps of the just-finished recording into the Journal as a single entry
    /// (counted 1 per recording). Prefer the destination dialog path which embeds <c>csx</c>.
    /// Kept for legacy callers; no-op if empty.
    /// </summary>
    private void CaptureRecordingToJournal()
    {
        List<string> steps;
        string label;
        string? url;
        lock (_currentRecordingSteps)
        {
            if (_currentRecordingSteps.Count == 0) return;
            steps = new List<string>(_currentRecordingSteps);
            label = _currentRecordingLabel;
            url = _currentRecordingUrl;
            _currentRecordingSteps.Clear();
        }

        try { _sessionLogger.LogRecording(label, steps, url); }
        catch (Exception ex) { TrowserLog.Warn($"Capture recording to journal failed: {ex.Message}"); }
    }

    /// <summary>
    /// Record a human-readable narration line for a browser action (for "Add to bug" repro steps).
    /// Caller already filtered via <see cref="CapturedActionRouting"/>.
    /// </summary>
    private void RecordNarration(JsonElement action)
    {
        AppendNarration(ActionNarrator.Describe(action));
    }

    /// <summary>Record a navigation narration line.</summary>
    private void RecordNavigationNarration(string url)
    {
        if (string.IsNullOrWhiteSpace(url) || url.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return;
        AppendNarration(ActionNarrator.DescribeNavigation(url));
    }

    private void AppendNarration(string? line)
    {
        if (string.IsNullOrEmpty(line)) return;
        lock (_recentNarration)
        {
            _recentNarration.Add(line);
            if (_recentNarration.Count > MaxNarrationEntries)
                _recentNarration.RemoveAt(0);
        }

        // While recording, collect the step; it's logged to the Journal as a single entry when the
        // recording stops (toggle: "Recordings in textual format" in Session Log settings).
        if (_recorder.IsRecording)
        {
            lock (_currentRecordingSteps)
                _currentRecordingSteps.Add(line);
        }
    }

    /// <summary>Recent narration lines joined as newline-separated repro steps (most recent last).</summary>
    private string GetRecentNarration(int max = 15)
    {
        lock (_recentNarration)
        {
            if (_recentNarration.Count == 0) return "";
            var start = Math.Max(0, _recentNarration.Count - max);
            return string.Join("\n", _recentNarration.Skip(start));
        }
    }

    #endregion

    #region Add to bug (Pillar 3)

    /// <summary>
    /// Gather evidence at the point of the right-click and open the "Add to bug" dialog.
    /// Runs on the UI thread (invoked from the context-menu handler).
    /// </summary>
    private async Task ShowAddToBugDialogAsync(ContextMenuElementInfo? element)
    {
        if (_automationContext == null) return;

        try
        {
            StatusText.Text = "Capturing bug evidence…";

            string url = "";
            try { url = await _automationContext.GetCurrentUrl(); } catch { /* best effort */ }

            string? screenshotPath = null;
            try
            {
                var bytes = await _automationContext.ScreenshotToBytes();
                screenshotPath = SaveBugScreenshot(bytes);
            }
            catch (Exception ex) { TrowserLog.Warn($"Bug screenshot failed: {ex.Message}"); }

            var elementDesc = DescribeElement(element);
            var evidenceNotes = BuildEvidenceNotes(element);
            var steps = GetRecentNarration();

            var dialog = new BugCaptureDialog(this, elementDesc, url, steps, screenshotPath, evidenceNotes);
            var result = dialog.ShowDialog();
            if (result != true)
            {
                StatusText.Text = "Ready";
                return;
            }

            var fields = dialog.BuildFields();

            // Consolidation (P1): attach a human pointer to the bug so the element + frozen crop
            // live in the shared pointer store and can be re-rendered from the bug entry later.
            if (element != null && element.HasTarget)
            {
                try
                {
                    var pointer = await CreateHumanPointerFromElementAsync(
                        _automationContext, element, Pointers.PointerKinds.Element,
                        caption: dialog.BugTitle, existingCropPath: screenshotPath);
                    fields["pointerId"] = pointer.Id;
                }
                catch (Exception ex) { TrowserLog.Warn($"Add-to-bug pointer failed: {ex.Message}"); }
            }

            var entry = _sessionLogger.LogTesterNote(NoteKinds.Bug, dialog.BugTitle, fields: fields, url: url);
            StatusText.Text = $"Bug added to journal (index {entry.Index})";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Add bug failed: {ex.Message}";
            TrowserLog.Error("Add to bug failed", ex);
        }
    }

    private static string DescribeElement(ContextMenuElementInfo? element)
    {
        if (element == null || !element.HasTarget) return "";
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(element.Role)) parts.Add(element.Role);
        if (!string.IsNullOrEmpty(element.Label)) parts.Add($"\"{element.Label}\"");
        else if (!string.IsNullOrEmpty(element.Text)) parts.Add($"\"{Truncate(element.Text, 60)}\"");
        if (parts.Count == 0 && !string.IsNullOrEmpty(element.Tag)) parts.Add($"<{element.Tag}>");
        var desc = string.Join(" ", parts);
        if (!string.IsNullOrEmpty(element.Selector)) desc += $"  [{element.Selector}]";
        return desc.Trim();
    }

    /// <summary>Assemble auto-captured evidence (console errors, failed requests) into a notes block.</summary>
    private string BuildEvidenceNotes(ContextMenuElementInfo? element)
    {
        var sb = new StringBuilder();

        try
        {
            var consoleErrors = _automationContext?.GetPageConsoleErrors() ?? new();
            if (consoleErrors.Count > 0)
            {
                sb.AppendLine($"Console errors ({consoleErrors.Count}):");
                foreach (var c in consoleErrors.TakeLast(5))
                    sb.AppendLine($"  - {Truncate(c.Message, 200)}");
            }
        }
        catch { /* best effort */ }

        try
        {
            var netErrors = _automationContext?.ActiveTab?.Network?.FindPageErrors() ?? new();
            if (netErrors.Count > 0)
            {
                sb.AppendLine($"Failed requests ({netErrors.Count}):");
                foreach (var n in netErrors.TakeLast(5))
                    sb.AppendLine($"  - {n.StatusCode} {n.Method} {Truncate(n.Url, 160)}");
            }
        }
        catch { /* best effort */ }

        return sb.ToString().TrimEnd();
    }

    private string? SaveBugScreenshot(byte[] bytes)
    {
        try
        {
            string dir;
            if (_sessionLogger.IsLogging && !string.IsNullOrEmpty(_sessionLogger.FilePath))
            {
                var logDir = Path.GetDirectoryName(Path.GetFullPath(_sessionLogger.FilePath))!;
                dir = Path.Combine(logDir, "screenshots");
            }
            else
            {
                dir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
            }
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, $"bug_{DateTime.Now:yyyyMMdd_HHmmss}.png");
            File.WriteAllBytes(path, bytes);
            return path;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Save bug screenshot failed: {ex.Message}");
            return null;
        }
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s : s[..max] + "…";

    #endregion
}
