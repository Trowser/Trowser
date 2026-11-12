using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Microsoft.Win32;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Laws;
using Trowser.Recording;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region Recording

    private async Task InjectRecordingScriptAsync(BrowserTab tab)
    {
        try
        {
            await tab.WebView.CoreWebView2.ExecuteScriptAsync(ScriptRecorder.InjectionScript);
        }
        catch (Exception ex) { TrowserLog.Warn($"Recording script injection failed: {ex.Message}"); }
    }

    private void RecordButton_Click(object sender, RoutedEventArgs e)
    {
        if (_recorder.IsRecording)
        {
            StopRecording();
        }
        else
        {
            StartRecording();
        }
    }

    private async void StartRecording()
    {
        if (_recorder.IsRecording) return;

        var url = _automationContext?.ActiveTab?.WebView?.CoreWebView2?.Source ?? "about:blank";
        try
        {
            _recorder.StartTemp(url);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not start recording: {ex.Message}";
            return;
        }

        BeginRecordingCapture("Recording", url);
        SetRecordingUiActive();

        var activeTab = _automationContext?.ActiveTab;
        if (activeTab != null)
            await InjectRecordingScriptAsync(activeTab);
    }

    private void StopRecording()
    {
        _ = FinalizeRecordingGuiAsync(closeAfter: false);
    }

    private void SetRecordingUiActive()
    {
        RecordButton.Content = "\u23F9";
        RecordButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C72B2B"));
        RecordButton.Foreground = new SolidColorBrush(Colors.White);
        RecordButton.ToolTip = "Stop recording";
        StatusText.Text = "Recording\u2026";
    }

    private void SetRecordingUiIdle()
    {
        RecordButton.Content = "\u23FA";
        RecordButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30"));
        RecordButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCCCCC"));
        RecordButton.ToolTip = "Record user actions to a .csx script";
    }

    /// <summary>
    /// Stop the recorder, show the destination dialog when there are steps, apply choices.
    /// When <paramref name="closeAfter"/> is true (window closing), Close() after Save/Discard.
    /// </summary>
    private async Task FinalizeRecordingGuiAsync(bool closeAfter)
    {
        if (!_recorder.IsRecording)
        {
            if (closeAfter)
            {
                _allowCloseDespiteRecording = true;
                Close();
            }
            return;
        }

        var result = _recorder.Stop();
        SetRecordingUiIdle();

        List<string> steps;
        lock (_currentRecordingSteps)
            steps = new List<string>(_currentRecordingSteps);

        if (result == null || result.ActionCount == 0)
        {
            result?.DeleteTempFiles();
            ClearRecordingCapture();
            StatusText.Text = "Nothing was recorded";
            if (closeAfter)
            {
                _allowCloseDespiteRecording = true;
                Close();
            }
            return;
        }

        var dlg = new RecordingStopDialog(this, result.StartUrl, steps, result.ActionCount);
        if (dlg.ShowDialog() != true)
        {
            result.DeleteTempFiles();
            ClearRecordingCapture();
            StatusText.Text = "Recording discarded";
            if (closeAfter)
            {
                _allowCloseDespiteRecording = true;
                Close();
            }
            return;
        }

        await ApplyRecordingDestinationsAsync(result, steps, dlg.Description,
            dlg.ToScriptConsole, dlg.ToFile, dlg.ToJournal, dlg.ToAi, filePathFromApi: null);

        ClearRecordingCapture();
        StatusText.Text = "Ready";

        if (closeAfter)
        {
            _allowCloseDespiteRecording = true;
            Close();
        }
    }

    /// <summary>
    /// Apply destination checkboxes / API options. Returns the saved file path and journal index when applicable.
    /// </summary>
    private async Task<(string? FilePath, int? JournalIndex)> ApplyRecordingDestinationsAsync(
        RecordingStopResult result,
        IReadOnlyList<string> steps,
        string? description,
        bool toConsole,
        bool toFile,
        bool toJournal,
        bool toAi,
        string? filePathFromApi)
    {
        var script = result.ScriptWithDescription(description);
        string? savedPath = null;
        int? journalIndex = null;

        if (toFile)
        {
            if (!string.IsNullOrWhiteSpace(filePathFromApi))
            {
                savedPath = await SaveRecordingToPathAsync(script, result, filePathFromApi!);
            }
            else
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "C# Script Files (*.csx)|*.csx|All Files (*.*)|*.*",
                    DefaultExt = ".csx",
                    Title = "Save Recording As",
                    FileName = RecordingStopResult.SuggestFileBaseName(description, result.StartedAt) + ".csx"
                };
                if (dialog.ShowDialog() == true)
                    savedPath = await SaveRecordingToPathAsync(script, result, dialog.FileName);
            }
        }

        if (toConsole)
        {
            ScriptInput.Text = script;
            IsScriptPanelVisible = true;
        }

        if (toJournal)
        {
            var label = string.IsNullOrWhiteSpace(description) ? "Recording" : description.Trim();
            try
            {
                var entry = _sessionLogger.LogRecording(label, steps, result.StartUrl,
                    csx: script, csxPath: savedPath, forceJournal: true);
                journalIndex = entry?.Index;
            }
            catch (Exception ex) { TrowserLog.Warn($"Capture recording to journal failed: {ex.Message}"); }
        }

        if (toAi)
            PrefillRecordingToChat(description, result.StartUrl, steps, script);

        // Keep temps only when File saved to the same temp path (unlikely); otherwise delete.
        if (savedPath == null
            || !string.Equals(savedPath, result.TempCsxPath, StringComparison.OrdinalIgnoreCase))
            result.DeleteTempFiles();
        else
        {
            // Script was written in place on the temp path — leave csx; drop narration sidecar if unused.
            try
            {
                if (!string.IsNullOrEmpty(result.TempNarrationPath)
                    && !string.Equals(
                        Path.Combine(Path.GetDirectoryName(savedPath) ?? "",
                            Path.GetFileNameWithoutExtension(savedPath) + "_text.md"),
                        result.TempNarrationPath,
                        StringComparison.OrdinalIgnoreCase)
                    && File.Exists(result.TempNarrationPath))
                    File.Delete(result.TempNarrationPath);
            }
            catch { /* best effort */ }
        }

        await Task.CompletedTask;
        return (savedPath, journalIndex);
    }

    private async Task<string?> SaveRecordingToPathAsync(string script, RecordingStopResult result, string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            await File.WriteAllTextAsync(path, script, new UTF8Encoding(false));

            // Sidecar narration next to the chosen .csx (File destination only).
            try
            {
                var narrationPath = Path.Combine(
                    Path.GetDirectoryName(path) ?? "",
                    Path.GetFileNameWithoutExtension(path) + "_text.md");
                var narration = result.Narration;
                if (string.IsNullOrWhiteSpace(narration) && !string.IsNullOrEmpty(result.TempNarrationPath)
                    && File.Exists(result.TempNarrationPath))
                    narration = await File.ReadAllTextAsync(result.TempNarrationPath);
                if (!string.IsNullOrWhiteSpace(narration))
                    await File.WriteAllTextAsync(narrationPath, narration, new UTF8Encoding(false));
            }
            catch (Exception ex) { TrowserLog.Warn($"Recorder narration sidecar save failed: {ex.Message}"); }

            return path;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Recorder save failed: {ex.Message}");
            StatusText.Text = $"Could not save recording: {ex.Message}";
            return null;
        }
    }

    private void PrefillRecordingToChat(string? description, string startUrl, IReadOnlyList<string> steps, string script)
    {
        var sb = new StringBuilder();
        sb.AppendLine("I recorded this interaction sequence. Help me turn it into a solid test or investigate issues:");
        sb.AppendLine();
        if (!string.IsNullOrWhiteSpace(description))
            sb.AppendLine($"Description: {description.Trim()}");
        if (!string.IsNullOrWhiteSpace(startUrl))
            sb.AppendLine($"Start URL: {startUrl}");
        sb.AppendLine();
        if (steps.Count > 0)
        {
            sb.AppendLine("Steps:");
            foreach (var step in steps)
                sb.AppendLine($"- {step}");
            sb.AppendLine();
        }
        sb.AppendLine("Recorded .csx script:");
        sb.AppendLine("```csharp");
        sb.AppendLine(script.TrimEnd());
        sb.AppendLine("```");

        IsChatPanelVisible = true;
        ChatPanelControl.PrefillInput(sb.ToString());
    }

    private void ClearRecordingCapture()
    {
        lock (_currentRecordingSteps)
        {
            _currentRecordingSteps.Clear();
            _currentRecordingLabel = "Recording";
            _currentRecordingUrl = null;
        }
    }

    /// <summary>API/MCP: start recording to temp. Returns error message or null on success.</summary>
    internal string? ApiStartRecording()
    {
        if (_recorder.IsRecording)
            return "Recording already in progress.";

        var url = _automationContext?.ActiveTab?.WebView?.CoreWebView2?.Source ?? "about:blank";
        try
        {
            _recorder.StartTemp(url);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }

        BeginRecordingCapture("Recording", url);
        SetRecordingUiActive();

        var activeTab = _automationContext?.ActiveTab;
        if (activeTab != null)
            _ = InjectRecordingScriptAsync(activeTab);

        return null;
    }

    /// <summary>API/MCP: recording status snapshot.</summary>
    internal object ApiRecordingStatus()
    {
        return new
        {
            recording = _recorder.IsRecording,
            startUrl = _recorder.StartUrl,
            startedAt = _recorder.StartedAt?.ToString("o"),
            actionCount = _recorder.ActionCount
        };
    }

    /// <summary>
    /// API/MCP stop: no dialog. <paramref name="path"/> writes via ExportPathGuard when non-null.
    /// </summary>
    internal async Task<object> ApiStopRecordingAsync(string? description, bool toJournal, string? path)
    {
        if (!_recorder.IsRecording)
        {
            return new
            {
                recording = false,
                script = (string?)null,
                narration = (string?)null,
                startUrl = (string?)null,
                actionCount = 0,
                journalIndex = (int?)null,
                filePath = (string?)null,
                message = "No recording in progress."
            };
        }

        var result = _recorder.Stop();
        SetRecordingUiIdle();

        List<string> steps;
        lock (_currentRecordingSteps)
            steps = new List<string>(_currentRecordingSteps);

        if (result == null || result.ActionCount == 0)
        {
            result?.DeleteTempFiles();
            ClearRecordingCapture();
            return new
            {
                recording = false,
                script = result?.Script ?? "",
                narration = result?.Narration ?? "",
                startUrl = result?.StartUrl,
                actionCount = 0,
                journalIndex = (int?)null,
                filePath = (string?)null,
                message = "Nothing was recorded."
            };
        }

        var toFile = !string.IsNullOrWhiteSpace(path);
        var (savedPath, journalIndex) = await ApplyRecordingDestinationsAsync(
            result, steps, description,
            toConsole: false, toFile: toFile, toJournal: toJournal, toAi: false,
            filePathFromApi: path);

        ClearRecordingCapture();

        return new
        {
            recording = false,
            script = result.ScriptWithDescription(description),
            narration = result.Narration,
            startUrl = result.StartUrl,
            actionCount = result.ActionCount,
            journalIndex,
            filePath = savedPath
        };
    }

    private const string DialogInterceptionScript = """
        (function() {
            if (window.__trowserDialogHooked) return;
            window.__trowserDialogHooked = true;
            window.__trowserDialog = { last: null, accept: true, promptText: null };

            function notifyDialog(info) {
                window.__trowserDialog.last = info;
                try { window.chrome.webview.postMessage({ type: '__trowser_dialog', dialog: info }); } catch(e) {}
            }

            window.alert = function(msg) {
                notifyDialog({ type: 'alert', message: String(msg || ''), timestamp: new Date().toISOString() });
            };

            window.confirm = function(msg) {
                notifyDialog({ type: 'confirm', message: String(msg || ''), timestamp: new Date().toISOString() });
                return window.__trowserDialog.accept;
            };

            window.prompt = function(msg, defaultVal) {
                notifyDialog({
                    type: 'prompt', message: String(msg || ''),
                    defaultValue: defaultVal !== undefined ? String(defaultVal) : null,
                    timestamp: new Date().toISOString()
                });
                if (!window.__trowserDialog.accept) return null;
                return window.__trowserDialog.promptText !== null
                    ? window.__trowserDialog.promptText
                    : (defaultVal !== undefined ? String(defaultVal) : '');
            };
        })();
        """;

    private async void Tab_ContextMenuRequestedAsync(BrowserTab tab, CoreWebView2ContextMenuRequestedEventArgs args)
    {
        if (tab.SuppressNextContextMenu)
        {
            tab.SuppressNextContextMenu = false;
            args.Handled = true;
            return;
        }

        if (!IsActiveTab(tab)) return;

        var deferral = args.GetDeferral();
        try
        {
            await PrepareContextMenuTargetAsync(tab, args);
            BuildContextMenuItems(tab, args);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Context menu setup failed: {ex.Message}");
        }
        finally
        {
            deferral.Complete();
        }
    }

    private async Task PrepareContextMenuTargetAsync(BrowserTab tab, CoreWebView2ContextMenuRequestedEventArgs args)
    {
        tab.LastContextMenuSelector = null;
        tab.LastContextMenuElement = null;
        var coreWv2 = tab.WebView.CoreWebView2;
        bool recording = _recorder.IsRecording;
        bool logging = _sessionLogger.IsLogging;
        const string readDataJs = "JSON.stringify(window.__trowserRightClickData || {})";

        if (recording || logging)
        {
            var raw = await coreWv2.ExecuteScriptAsync(readDataJs);
            tab.LastContextMenuElement = ContextMenuElementInfo.ParseFromJson(raw);
            tab.LastContextMenuSelector = tab.LastContextMenuElement?.Selector;
            return;
        }

        var loc = args.Location;
        var script = RunScriptContextScript.BuildElementAtPointScript(loc.X, loc.Y);
        var rawPoint = await coreWv2.ExecuteScriptAsync(script);
        tab.LastContextMenuElement = ContextMenuElementInfo.ParseFromJson(rawPoint);
        tab.LastContextMenuSelector = tab.LastContextMenuElement?.Selector;
    }

    private void BuildContextMenuItems(BrowserTab tab, CoreWebView2ContextMenuRequestedEventArgs args)
    {
        bool recording = _recorder.IsRecording;
        bool logging = _sessionLogger.IsLogging;

        var env = tab.WebView.CoreWebView2.Environment;
        var coreWv2 = tab.WebView.CoreWebView2;
        var menuItems = args.MenuItems;

        var readDataJs = "JSON.stringify(window.__trowserRightClickData || {})";

        var runScriptItem = env.CreateContextMenuItem(
            "Run Script", null, CoreWebView2ContextMenuItemKind.Command);
        runScriptItem.CustomItemSelected += (_, _) =>
        {
            try
            {
                var selector = tab.LastContextMenuSelector;
                if (string.IsNullOrWhiteSpace(selector))
                {
                    Dispatcher.Invoke(() =>
                        StatusText.Text = "Run Script: no element selector at this location.");
                    return;
                }

                Dispatcher.Invoke(() =>
                {
                    IsScriptPanelVisible = true;
                    if (_automationContext != null)
                        _automationContext.This = selector;
                    _ = RunCurrentScriptAsync();
                });
            }
            catch (Exception ex) { TrowserLog.Warn($"Run Script failed: {ex.Message}"); }
        };

        var declareLawItem = env.CreateContextMenuItem(
            "Declare as Law", null, CoreWebView2ContextMenuItemKind.Command);
        declareLawItem.CustomItemSelected += (_, _) =>
        {
            try
            {
                var element = tab.LastContextMenuElement;
                if (element == null || !element.HasTarget)
                {
                    Dispatcher.Invoke(() =>
                        StatusText.Text = "Declare as Law: no element at this location.");
                    return;
                }

                Dispatcher.Invoke(() => _ = DeclareElementAsLawAsync(element));
            }
            catch (Exception ex) { TrowserLog.Warn($"Declare as Law failed: {ex.Message}"); }
        };

        var sendToChatItem = env.CreateContextMenuItem(
            "Send to Chat", null, CoreWebView2ContextMenuItemKind.Command);
        sendToChatItem.CustomItemSelected += (_, _) =>
        {
            try
            {
                var element = tab.LastContextMenuElement;
                if (element == null || !element.HasTarget)
                {
                    Dispatcher.Invoke(() =>
                        StatusText.Text = "Send to Chat: no element at this location.");
                    return;
                }

                Dispatcher.Invoke(() => _ = SendElementToChatAsync(element));
            }
            catch (Exception ex) { TrowserLog.Warn($"Send to Chat failed: {ex.Message}"); }
        };

        var attackFormItem = env.CreateContextMenuItem(
            "Attack this form", null, CoreWebView2ContextMenuItemKind.Command);
        attackFormItem.CustomItemSelected += (_, _) =>
        {
            try
            {
                var selector = tab.LastContextMenuSelector;
                Dispatcher.Invoke(() => RunQuicktestWithTarget(
                    "Trowser.Resources.Quicktests.Experimental.AttackForm.csx", selector));
            }
            catch (Exception ex) { TrowserLog.Warn($"Attack this form failed: {ex.Message}"); }
        };

        var addToBugItem = env.CreateContextMenuItem(
            "Add bug", null, CoreWebView2ContextMenuItemKind.Command);
        addToBugItem.CustomItemSelected += (_, _) =>
        {
            try
            {
                var element = tab.LastContextMenuElement;
                Dispatcher.Invoke(() => _ = ShowAddToBugDialogAsync(element));
            }
            catch (Exception ex) { TrowserLog.Warn($"Add to bug failed: {ex.Message}"); }
        };

        menuItems.Insert(0, env.CreateContextMenuItem(
            "", null, CoreWebView2ContextMenuItemKind.Separator));
        menuItems.Insert(0, addToBugItem);
        menuItems.Insert(0, attackFormItem);
        menuItems.Insert(0, sendToChatItem);
        menuItems.Insert(0, declareLawItem);
        menuItems.Insert(0, runScriptItem);

        if (!recording && !logging)
            return;

        var assertItem = env.CreateContextMenuItem(
            "Assert text", null, CoreWebView2ContextMenuItemKind.Command);
        assertItem.CustomItemSelected += async (s, e) =>
        {
            try
            {
                var raw = await coreWv2.ExecuteScriptAsync(readDataJs);
                if (raw == "null" || raw == "undefined") return;
                if (raw.StartsWith('"'))
                    raw = System.Text.Json.JsonSerializer.Deserialize<string>(raw) ?? "";
                using var doc = System.Text.Json.JsonDocument.Parse(raw);
                var text = doc.RootElement.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(text)) return;

                if (recording)
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(
                        new { type = "assert", text = text.Trim() });
                    using var assertDoc = System.Text.Json.JsonDocument.Parse(json);
                    _recorder.RecordAction(assertDoc.RootElement);
                }

                if (logging)
                    _sessionLogger.LogAssert(text.Trim());
            }
            catch (Exception ex) { TrowserLog.Warn($"Assert recording failed: {ex.Message}"); }
        };

        var interestItem = env.CreateContextMenuItem(
            "Element of interest", null, CoreWebView2ContextMenuItemKind.Command);
        interestItem.CustomItemSelected += async (s, e) =>
        {
            try
            {
                var raw = await coreWv2.ExecuteScriptAsync(readDataJs);
                if (raw == "null" || raw == "undefined") return;
                if (raw.StartsWith('"'))
                    raw = System.Text.Json.JsonSerializer.Deserialize<string>(raw) ?? "";

                using var doc = System.Text.Json.JsonDocument.Parse(raw);
                var root = doc.RootElement;
                if (!root.TryGetProperty("tag", out var tagProp) || string.IsNullOrEmpty(tagProp.GetString()))
                    return;

                var tag = tagProp.GetString() ?? "";
                var text = root.TryGetProperty("text", out var tx) ? tx.GetString() ?? "" : "";
                var role = root.TryGetProperty("role", out var r) ? r.GetString() ?? "" : "";
                var label = root.TryGetProperty("label", out var l) ? l.GetString() ?? "" : "";
                var inputType = root.TryGetProperty("inputType", out var it) ? it.GetString() ?? "" : "";
                var href = root.TryGetProperty("href", out var h) ? h.GetString() ?? "" : "";

                if (recording)
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        type = "elementOfInterest",
                        tag, text, role, label, inputType, href
                    });
                    using var eoiDoc = System.Text.Json.JsonDocument.Parse(json);
                    _recorder.RecordAction(eoiDoc.RootElement);
                }

                if (logging)
                    _sessionLogger.LogElementOfInterest(tag, text, role, label);

                // Consolidation (P1): also drop a human pointer so the element of interest lands in
                // the shared pointer store (symmetric with agent browser_point), with a frozen crop.
                var eoiElement = tab.LastContextMenuElement;
                var ctx = _automationContext;
                if (ctx != null && eoiElement != null && eoiElement.HasTarget)
                {
                    var caption = DescribeElement(eoiElement);
                    await CreateHumanPointerFromElementAsync(ctx, eoiElement, Pointers.PointerKinds.Element,
                        caption: string.IsNullOrWhiteSpace(caption) ? null : caption);
                }
            }
            catch (Exception ex) { TrowserLog.Warn($"Element of interest recording failed: {ex.Message}"); }
        };

        menuItems.Insert(0, env.CreateContextMenuItem(
            "", null, CoreWebView2ContextMenuItemKind.Separator));
        menuItems.Insert(0, interestItem);
        menuItems.Insert(0, assertItem);
    }

    #endregion

    #region Play Script File

    private void PlayButton_Click(object sender, RoutedEventArgs e)
    {
        if (_playRun != null || _scriptConsoleRun != null) return;

        var dialog = new OpenFileDialog
        {
            Filter = "Scripts and scenarios (*.csx;*.trw;*.json)|*.csx;*.trw;*.json|Trowser scenario (*.trw)|*.trw|JSON scenario (*.json)|*.json|C# script (*.csx)|*.csx|All files (*.*)|*.*",
            Title = "Select script or scenario to run"
        };

        if (dialog.ShowDialog() != true) return;

        _ = RunScriptFileAsync(dialog.FileName);
    }

    private async Task RunScriptFileAsync(string filePath)
    {
        if (_playRun != null || _scriptConsoleRun != null) return;

        var ext = Path.GetExtension(filePath);
        var isScenario = string.Equals(ext, ".trw", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase);

        if (isScenario)
        {
            if (_automationContext == null)
            {
                LogToOutput("[Error] Browser not ready. Wait for the page to finish loading.");
                return;
            }

            if (_apiServer?.IsRunning != true)
            {
                LogToOutput("[Error] Turn on the REST API (status bar) to run .trw/.json scenarios.");
                return;
            }
        }
        else
        {
            if (_scriptEngine == null || _automationContext == null)
            {
                LogToOutput("[Error] Script engine not initialized. Wait for browser to finish loading.");
                return;
            }
        }

        string? code = null;
        if (!isScenario)
        {
            try
            {
                code = await File.ReadAllTextAsync(filePath);
            }
            catch (Exception ex)
            {
                LogToOutput($"[Error] Could not read file: {ex.Message}");
                return;
            }

            if (string.IsNullOrWhiteSpace(code))
                return;
        }

        var fileName = Path.GetFileName(filePath);
        _playRun = new ScriptRunControl();
        _automationContext!.ScriptRunControl = _playRun;
        _playRunStatusText = $"Running: {fileName}";
        SetPlayRunUiRunning();
        ClearOutput();
        LogToOutput($"[Play] {fileName}");
        StatusText.Text = $"Running: {fileName}";

        _automationContext.Assert.Reset();

        try
        {
            if (isScenario)
                await RunScenarioFileAsync(filePath, fileName, _playRun.StopToken);
            else
                await RunCsxScriptFileAsync(fileName, code!, _playRun);
        }
        catch (Exception ex)
        {
            LogColoredToOutput($"[Error] {ex.Message}", "#F44747");
            StatusText.Text = $"{fileName} failed";
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

    private async Task<ScriptResult> ExecuteScriptOffUiThreadAsync(string code, ScriptRunControl runControl)
    {
        // Scripts must not run on the WPF UI thread: playbook steps and security probes
        // call async WebView APIs and sync-over-async anywhere would deadlock the dispatcher.
        return await Task.Run(
            async () => await _scriptEngine!.ExecuteAsync(code, runControl.StopToken, runControl),
            runControl.StopToken);
    }

    private async Task<ScriptResult> ExecuteScriptOffUiThreadAsync(string code, CancellationToken ct)
    {
        return await Task.Run(async () => await _scriptEngine!.ExecuteAsync(code, ct), ct);
    }

    private async Task RunCsxScriptFileAsync(string fileName, string code, ScriptRunControl runControl)
    {
        var result = await ExecuteScriptOffUiThreadAsync(code, runControl);

        if (result.IsCancelled)
        {
            LogColoredToOutput($"[Cancelled] Script stopped by user ({result.ElapsedMs}ms)", "#CCA700");
            StatusText.Text = $"Script cancelled after {result.ElapsedMs}ms";
        }
        else if (result.Success)
        {
            if (result.ReturnValue != null)
                LogColoredToOutput($"[Result] {result.ReturnValue}", "#DCDCAA");

            if (_automationContext!.Assert.TotalCount > 0)
                _automationContext.Assert.Summary();

            StatusText.Text = $"{fileName} completed in {result.ElapsedMs}ms";

            if (_automationContext.Assert.TotalCount > 0)
            {
                StatusText.Text += _automationContext.Assert.AllPassed
                    ? $" | ALL {_automationContext.Assert.PassCount} PASSED"
                    : $" | {_automationContext.Assert.FailCount} FAILED";
            }
        }
        else
        {
            LogColoredToOutput($"[Error] {result.Error}", "#F44747");
            StatusText.Text = $"{fileName} failed";
        }
    }

    private async Task RunScenarioFileAsync(string filePath, string fileName, CancellationToken ct)
    {
        const int bodyPreviewChars = 600;

        var fullPath = Path.GetFullPath(filePath);
        var payload = JsonSerializer.Serialize(new { file = fullPath });
        using var request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{_apiPort}/api/test-scenario");
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        if (_apiKeyRequired && !string.IsNullOrEmpty(_apiKey))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };

        try
        {
            using var response = await client.SendAsync(request, ct);
            var responseText = await response.Content.ReadAsStringAsync(ct);

            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(responseText) ? "{}" : responseText);
            var root = doc.RootElement;

            if (!response.IsSuccessStatusCode)
            {
                var err = TryGetJsonString(root, "error") ?? response.ReasonPhrase ?? $"HTTP {(int)response.StatusCode}";
                LogColoredToOutput($"[Error] {err}", "#F44747");
                StatusText.Text = $"{fileName} failed";
                return;
            }

            if (root.TryGetProperty("success", out var successEl) && successEl.ValueKind == JsonValueKind.False)
            {
                var err = TryGetJsonString(root, "error") ?? "Unknown error";
                LogColoredToOutput($"[Error] {err}", "#F44747");
                StatusText.Text = $"{fileName} failed";
                return;
            }

            if (!root.TryGetProperty("data", out var data))
            {
                LogColoredToOutput("[Error] Invalid response: missing data object.", "#F44747");
                StatusText.Text = $"{fileName} failed";
                return;
            }

            var scenarioName = data.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String
                ? nameEl.GetString()
                : null;
            if (!string.IsNullOrWhiteSpace(scenarioName))
                LogColoredToOutput($"Scenario: {scenarioName}", "#569CD6");

            LogColoredToOutput("Steps:", "#858585");

            if (data.TryGetProperty("results", out var results) && results.ValueKind == JsonValueKind.Array)
            {
                foreach (var step in results.EnumerateArray())
                    LogScenarioStepLine(step, bodyPreviewChars);
            }

            var stepCount = data.TryGetProperty("stepCount", out var scEl) && scEl.ValueKind == JsonValueKind.Number
                ? scEl.GetInt32()
                : 0;
            var stoppedEarly = data.TryGetProperty("stoppedEarly", out var stEl) && stEl.ValueKind == JsonValueKind.True;

            if (stoppedEarly)
                LogColoredToOutput("Stopped early (stop on error or step cap).", "#CCA700");

            var tailColor = stoppedEarly ? "#CCA700" : "#6A9955";
            LogColoredToOutput($"Done — {stepCount} step(s) reported.", tailColor);

            StatusText.Text = stoppedEarly
                ? $"{fileName} finished (stopped early)"
                : $"{fileName} completed";

            if (_automationContext!.Assert.TotalCount > 0)
            {
                _automationContext.Assert.Summary();
                StatusText.Text += _automationContext.Assert.AllPassed
                    ? $" | ALL {_automationContext.Assert.PassCount} PASSED"
                    : $" | {_automationContext.Assert.FailCount} FAILED";
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            LogColoredToOutput("[Cancelled] Scenario stopped by user.", "#CCA700");
            StatusText.Text = "Scenario cancelled";
        }
        catch (HttpRequestException ex)
        {
            LogColoredToOutput($"[Error] Could not reach local API: {ex.Message}", "#F44747");
            StatusText.Text = "Scenario failed";
        }
    }

    private void LogScenarioStepLine(JsonElement step, int bodyPreviewChars)
    {
        var index = step.TryGetProperty("index", out var ix) && ix.ValueKind == JsonValueKind.Number ? ix.GetInt32() : -1;
        var method = step.TryGetProperty("method", out var me) && me.ValueKind == JsonValueKind.String ? me.GetString() : null;
        var path = step.TryGetProperty("path", out var pe) && pe.ValueKind == JsonValueKind.String ? pe.GetString() : null;
        var err = step.TryGetProperty("error", out var ee) && ee.ValueKind == JsonValueKind.String ? ee.GetString() : null;
        var stepId = step.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String ? idEl.GetString() : null;

        var ok = true;
        if (step.TryGetProperty("success", out var se) && se.ValueKind is JsonValueKind.True or JsonValueKind.False)
            ok = se.GetBoolean();

        int? statusCode = null;
        if (step.TryGetProperty("statusCode", out var st) && st.ValueKind == JsonValueKind.Number)
            statusCode = st.GetInt32();

        // Header line: [index] METHOD /path  HTTP status  OK/FAIL
        var head = index >= 0 ? $"[{index}]" : "[?]";
        if (!string.IsNullOrEmpty(stepId))
            head += $" ({stepId})";
        if (method != null && path != null)
            head += $" {method} {path}";
        else if (path != null)
            head += $" {path}";
        else if (method != null)
            head += $" {method}";

        if (statusCode.HasValue)
            head += $"  HTTP {statusCode}";

        head += ok ? "  OK" : "  FAIL";

        LogColoredToOutput(head, ok ? "#6A9955" : "#F44747");

        if (!string.IsNullOrEmpty(err))
            LogColoredToOutput($"  {err}", "#F44747");

        // Extract response data for detail display
        JsonElement? data = null;
        if (step.TryGetProperty("body", out var body) && body.ValueKind == JsonValueKind.Object
            && body.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object)
        {
            data = d;
        }

        // Extract request body for detail display
        JsonElement? reqBody = null;
        if (step.TryGetProperty("requestBody", out var rb) && rb.ValueKind == JsonValueKind.Object)
            reqBody = rb;

        // Show context-specific details based on endpoint
        LogStepDetails(path, method, ok, data, reqBody, bodyPreviewChars);

        // Show captured variables
        if (step.TryGetProperty("captured", out var capturedEl) && capturedEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in capturedEl.EnumerateObject())
            {
                var val = prop.Value.ValueKind == JsonValueKind.String
                    ? $"\"{prop.Value.GetString()}\""
                    : prop.Value.GetRawText();
                if (val.Length > 120) val = val[..117] + "...";
                LogColoredToOutput($"  📋 Captured: {prop.Name} = {val}", "#DCDCAA");
            }
        }

        // For failed steps without specific handling, show raw body preview
        if (!ok && data == null && step.TryGetProperty("body", out var rawBody)
            && rawBody.ValueKind is not JsonValueKind.Undefined and not JsonValueKind.Null)
        {
            var preview = TruncateJsonElement(rawBody, bodyPreviewChars);
            if (preview.Length > 0)
                LogColoredToOutput($"  {preview}", "#9CDCFE");
        }
    }

    /// <summary>
    /// Extracts and displays meaningful details from step results based on the endpoint type.
    /// </summary>
    private void LogStepDetails(string? path, string? method, bool ok, JsonElement? data, JsonElement? reqBody, int maxChars)
    {
        if (path == null) return;

        switch (path)
        {
            case "/api/navigate":
                if (reqBody.HasValue)
                    LogDetailField(reqBody.Value, "url", "  → ", "#DCDCAA");
                if (data.HasValue)
                    LogDetailField(data.Value, "title", "  Title: ", "#9CDCFE");
                break;

            case "/api/click":
                LogClickOrTypeDetails(reqBody, data, "Clicked");
                break;

            case "/api/type":
                LogClickOrTypeDetails(reqBody, data, "Typed into");
                if (reqBody.HasValue)
                    LogDetailField(reqBody.Value, "text", "  Text: ", "#CE9178");
                break;

            case "/api/select":
                LogClickOrTypeDetails(reqBody, data, "Selected in");
                if (reqBody.HasValue)
                    LogDetailField(reqBody.Value, "value", "  Value: ", "#CE9178");
                break;

            case "/api/key":
                if (reqBody.HasValue)
                    LogDetailField(reqBody.Value, "key", "  Key: ", "#DCDCAA");
                break;

            case "/api/execute-js":
                if (data.HasValue && data.Value.TryGetProperty("result", out var jsResult)
                    && jsResult.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
                {
                    var resultText = jsResult.ValueKind == JsonValueKind.String
                        ? jsResult.GetString() ?? ""
                        : jsResult.GetRawText();
                    if (resultText.Length > maxChars) resultText = resultText[..maxChars] + "…";
                    LogColoredToOutput($"  Result: {resultText}", "#9CDCFE");
                }
                break;

            case "/api/journal":
                if (method == "POST")
                    LogJournalEntry(reqBody, data);
                break;

            default:
                // Assertion endpoints
                if (path.StartsWith("/api/assert/"))
                    LogAssertionDetails(path, ok, reqBody, data);
                // For failed steps on other endpoints, show error from response
                else if (!ok && data.HasValue)
                    LogDetailField(data.Value, "error", "  ", "#F44747");
                break;
        }
    }

    private void LogClickOrTypeDetails(JsonElement? reqBody, JsonElement? data, string verb)
    {
        if (reqBody == null) return;
        var rb = reqBody.Value;

        // Show what element was targeted
        string? target = null;
        if (rb.TryGetProperty("label", out var lbl) && lbl.ValueKind == JsonValueKind.String)
            target = $"\"{lbl.GetString()}\"";
        else if (rb.TryGetProperty("byText", out var bt) && bt.ValueKind == JsonValueKind.String)
            target = $"text \"{bt.GetString()}\"";
        else if (rb.TryGetProperty("selector", out var sel) && sel.ValueKind == JsonValueKind.String)
            target = sel.GetString();
        else if (rb.TryGetProperty("ref", out var refEl) && refEl.ValueKind == JsonValueKind.Number)
            target = $"ref {refEl.GetInt32()}";
        else if (rb.TryGetProperty("role", out var role) && role.ValueKind == JsonValueKind.String)
        {
            target = role.GetString();
            if (rb.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
                target += $" \"{name.GetString()}\"";
        }

        if (target != null)
            LogColoredToOutput($"  {verb}: {target}", "#9CDCFE");
    }

    private void LogJournalEntry(JsonElement? reqBody, JsonElement? data)
    {
        // Show the journal kind and severity
        string? kind = null;
        string? severity = null;
        if (data.HasValue)
        {
            kind = TryGetJsonString(data.Value, "kind");
            severity = TryGetJsonString(data.Value, "severity");
        }

        var kindLabel = kind ?? "note";
        var kindColor = kindLabel switch
        {
            "bug" => "#F44747",
            "enhancement" => "#569CD6",
            "observation" => "#DCDCAA",
            _ => "#6A9955"
        };

        var header = $"  📝 Journal ({kindLabel})";
        if (severity != null && severity != "info")
            header += $" [{severity}]";
        LogColoredToOutput(header, kindColor);

        // Show the note text from the request body
        if (reqBody.HasValue)
        {
            var noteText = TryGetJsonString(reqBody.Value, "note")
                        ?? TryGetJsonString(reqBody.Value, "text")
                        ?? TryGetJsonString(reqBody.Value, "title");
            if (!string.IsNullOrWhiteSpace(noteText))
                LogColoredToOutput($"  {noteText}", "#D4D4D4");

            // Show structured fields (bug report details)
            foreach (var fieldName in new[] { "steps", "expected", "actual", "notes" })
            {
                if (reqBody.Value.TryGetProperty(fieldName, out var fv) && fv.ValueKind == JsonValueKind.String)
                {
                    var fieldText = fv.GetString();
                    if (!string.IsNullOrWhiteSpace(fieldText))
                    {
                        var label = char.ToUpper(fieldName[0]) + fieldName[1..];
                        LogColoredToOutput($"  {label}: {fieldText}", "#858585");
                    }
                }
            }
        }
    }

    private void LogAssertionDetails(string path, bool ok, JsonElement? reqBody, JsonElement? data)
    {
        // Show assertion message from request
        string? message = null;
        if (reqBody.HasValue)
            message = TryGetJsonString(reqBody.Value, "message");

        // Show expected value
        string? expected = null;
        if (reqBody.HasValue)
            expected = TryGetJsonString(reqBody.Value, "expected")
                    ?? TryGetJsonString(reqBody.Value, "text");

        var icon = ok ? "✓" : "✗";
        var detail = message ?? path.Replace("/api/assert/", "assert ");
        if (expected != null)
            detail += $" — expected: \"{expected}\"";

        LogColoredToOutput($"  {icon} {detail}", ok ? "#6A9955" : "#F44747");

        // Show actual value on failure
        if (!ok && data.HasValue)
        {
            var actual = TryGetJsonString(data.Value, "actual")
                      ?? TryGetJsonString(data.Value, "foundText");
            if (actual != null)
                LogColoredToOutput($"  Actual: \"{actual}\"", "#CE9178");
        }
    }

    private void LogDetailField(JsonElement el, string fieldName, string prefix, string color)
    {
        if (el.TryGetProperty(fieldName, out var val) && val.ValueKind == JsonValueKind.String)
        {
            var text = val.GetString();
            if (!string.IsNullOrWhiteSpace(text))
                LogColoredToOutput($"{prefix}{text}", color);
        }
    }

    private static string? TryGetJsonString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

    private static string TruncateJsonElement(JsonElement el, int maxChars)
    {
        var raw = el.GetRawText();
        return raw.Length <= maxChars ? raw : raw[..maxChars] + "…";
    }

    #endregion

    #region Script Console

    private void OpenLawSourceInScriptConsole(string source)
    {
        try
        {
            string? code = null;
            if (source.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase))
            {
                var virtualPath = source["embedded:".Length..].Replace('\\', '.').Replace(".csx", "");
                var assembly = Assembly.GetExecutingAssembly();
                var resource = assembly.GetManifestResourceNames()
                    .FirstOrDefault(n => n.Contains("Quicktests.Laws", StringComparison.Ordinal)
                                         && n.EndsWith(".csx", StringComparison.OrdinalIgnoreCase)
                                         && n.Contains(virtualPath.Split('.')[^1], StringComparison.OrdinalIgnoreCase));
                if (resource != null)
                {
                    using var stream = assembly.GetManifestResourceStream(resource);
                    if (stream != null)
                        using (var reader = new StreamReader(stream))
                            code = reader.ReadToEnd();
                }
            }
            else if (File.Exists(source))
                code = File.ReadAllText(source);

            if (string.IsNullOrEmpty(code))
            {
                StatusText.Text = "Could not open Law source.";
                return;
            }

            if (!code.Contains("CheckLaws", StringComparison.OrdinalIgnoreCase))
            {
                code = code.TrimEnd() + Environment.NewLine + Environment.NewLine +
                       "// Checks Laws declared above in this Run only (not all Shadow Laws):" + Environment.NewLine +
                       "await CheckLaws();" + Environment.NewLine;
            }

            ScriptInput.Text = code;
            IsScriptPanelVisible = true;
            StatusText.Text = "Law loaded into Script Console — Run declares Laws and runs CheckLaws()";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Open Law failed: {ex.Message}";
        }
    }

    private void WatchMode_Click(object sender, RoutedEventArgs e)
    {
        _isWatchModeActive = !_isWatchModeActive;

        if (_isWatchModeActive)
        {
            WatchModeButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF9552"));
            WatchModeButton.Foreground = new SolidColorBrush(Colors.White);
            StatusText.Text = "Watch mode ON — script runs on navigation; Shadow Laws enabled";
            if (!_securityShadow.Enabled)
                _securityShadow.Configure(true);
            _securityShadow.Config.LawsEnabled = true;
        }
        else
        {
            WatchModeButton.Background = Brushes.Transparent;
            WatchModeButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCCCCC"));
            StatusText.Text = "Watch mode OFF";
        }
    }

    private async void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        if (_automationContext == null) return;

        try
        {
            var result = await _automationContext.ClearAll();
            StatusText.Text = result.Summary;
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Clear All error: {ex.Message}";
        }
    }

    private async Task RunWatchModeScriptAsync()
    {
        if (_scriptEngine == null || _automationContext == null) return;
        if (_scriptConsoleRun != null || _playRun != null) return;

        _watchModeRunning = true;
        try
        {
            await RunCurrentScriptAsync();
            if (_securityShadow.Config.LawsEnabled)
                await _lawService.CheckLawsAsync(scope: LawCheckScope.ScriptConsoleDeclared);
        }
        finally
        {
            _watchModeRunning = false;
        }
    }

    private async Task DeclareElementAsLawAsync(ContextMenuElementInfo element)
    {
        if (_automationContext == null) return;
        var urlText = await _automationContext.GetCurrentUrl();
        Uri? pageUrl = Uri.TryCreate(urlText, UriKind.Absolute, out var u) ? u : null;
        ScriptInput.Text = Trowser.Laws.LawCodeGenerator.FromElement(element, pageUrl, forScriptConsoleRun: true);
        IsScriptPanelVisible = true;
        StatusText.Text = "Law in Script Console — Run to try, then right-click editor → Save as Law";
    }

    private void WireScriptInputContextMenu()
    {
        if (ScriptInput.ContextMenu != null)
            return;

        var menu = new ContextMenu
        {
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30")),
            BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46"))
        };
        var saveItem = CreateDarkMenuItem("Save as Law...", (_, _) => _ = SaveScriptConsoleAsLawAsync());
        menu.Items.Add(saveItem);
        ScriptInput.ContextMenu = menu;
    }

    private async Task SaveScriptConsoleAsLawAsync()
    {
        var raw = ScriptInput.Text;
        if (string.IsNullOrWhiteSpace(raw) || !raw.Contains("Law(", StringComparison.Ordinal))
        {
            StatusText.Text = "Save as Law: script must declare at least one Law(...).";
            return;
        }

        LawService.EnsureUserLawsFolder();
        var dialog = new SaveFileDialog
        {
            Filter = "Law script (*.csx)|*.csx|All files (*.*)|*.*",
            DefaultExt = ".csx",
            Title = "Save as Law",
            InitialDirectory = LawService.UserLawsFolder,
            FileName = $"Declared-{DateTime.Now:yyyyMMdd-HHmmss}.csx"
        };

        if (dialog.ShowDialog() != true)
            return;

        try
        {
            var code = LawCodeGenerator.StripConsoleRunnerLines(raw);
            await File.WriteAllTextAsync(dialog.FileName, code);
            await _lawService.LoadLaws(dialog.FileName);
            StatusText.Text = $"Saved Law to {dialog.FileName} — Shadow loads it automatically";
        }
        catch (Exception ex)
        {
            LogToOutput($"[Error] Save as Law failed: {ex.Message}");
        }
    }


    private void RunScript_Click(object sender, RoutedEventArgs e)
    {
        if (_scriptConsoleRun != null || _playRun != null) return;
        _ = RunCurrentScriptAsync();
    }

    private void PauseScript_Click(object sender, RoutedEventArgs e)
    {
        ToggleScriptPause(_scriptConsoleRun, RunButton, PauseScriptButton, StopScriptButton, "\u25B6 Run", "Running script...");
    }

    private void StopScript_Click(object sender, RoutedEventArgs e)
    {
        _scriptConsoleRun?.Stop();
    }

    private void PausePlay_Click(object sender, RoutedEventArgs e)
    {
        ToggleScriptPause(_playRun, PlayButton, PausePlayButton, StopPlayButton, "\u25B6", _playRunStatusText);
    }

    private void StopPlay_Click(object sender, RoutedEventArgs e)
    {
        _playRun?.Stop();
    }

    private void ToggleScriptPause(
        ScriptRunControl? runControl,
        Button runButton,
        Button pauseButton,
        Button stopButton,
        string runLabel,
        string? runningStatusText)
    {
        if (runControl == null) return;

        if (runControl.IsPaused)
        {
            runControl.Resume();
            SetScriptRunUiRunning(runButton, pauseButton, stopButton);
            LogColoredToOutput("[Resumed] Script resumed", "#CCA700");
            if (runningStatusText != null)
                StatusText.Text = runningStatusText;
        }
        else
        {
            runControl.Pause();
            SetScriptRunUiPaused(runButton, pauseButton, stopButton);
            LogColoredToOutput("[Paused] Script paused — perform manual steps, then resume", "#CCA700");
            StatusText.Text = "Script paused";
        }
    }

    private void SetScriptConsoleRunUiIdle() =>
        SetScriptRunUiIdle(RunButton, PauseScriptButton, StopScriptButton, "\u25B6 Run");

    private void SetScriptConsoleRunUiRunning() =>
        SetScriptRunUiRunning(RunButton, PauseScriptButton, StopScriptButton);

    private void SetScriptConsoleRunUiPaused() =>
        SetScriptRunUiPaused(RunButton, PauseScriptButton, StopScriptButton);

    private void SetPlayRunUiIdle() =>
        SetScriptRunUiIdle(PlayButton, PausePlayButton, StopPlayButton, "\u25B6");

    private void SetPlayRunUiRunning() =>
        SetScriptRunUiRunning(PlayButton, PausePlayButton, StopPlayButton);

    private void SetPlayRunUiPaused() =>
        SetScriptRunUiPaused(PlayButton, PausePlayButton, StopPlayButton);

    private static void SetScriptRunUiIdle(Button runButton, Button pauseButton, Button stopButton, string runLabel)
    {
        runButton.Visibility = Visibility.Visible;
        pauseButton.Visibility = Visibility.Collapsed;
        stopButton.Visibility = Visibility.Collapsed;
        runButton.Content = runLabel;
        runButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#16825B"));
        runButton.Foreground = new SolidColorBrush(Colors.White);
        pauseButton.FontWeight = FontWeights.Normal;
    }

    private static void SetScriptRunUiRunning(Button runButton, Button pauseButton, Button stopButton)
    {
        runButton.Visibility = Visibility.Collapsed;
        pauseButton.Visibility = Visibility.Visible;
        stopButton.Visibility = Visibility.Visible;
        pauseButton.Content = ScriptPauseIcon;
        pauseButton.FontWeight = FontWeights.ExtraBold;
        pauseButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCA700"));
        pauseButton.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1E1E1E"));
        pauseButton.ToolTip = "Pause script";
    }

    private static void SetScriptRunUiPaused(Button runButton, Button pauseButton, Button stopButton)
    {
        runButton.Visibility = Visibility.Collapsed;
        pauseButton.Visibility = Visibility.Visible;
        stopButton.Visibility = Visibility.Visible;
        pauseButton.Content = "\u25B6";
        pauseButton.FontWeight = FontWeights.Normal;
        pauseButton.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#16825B"));
        pauseButton.Foreground = new SolidColorBrush(Colors.White);
        pauseButton.ToolTip = "Resume script";
    }

    private void ScriptInput_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control)
        {
            if (_scriptConsoleRun != null)
                _scriptConsoleRun.Stop();
            else
                _ = RunCurrentScriptAsync();
            e.Handled = true;
        }
        else if (e.Key == Key.K && Keyboard.Modifiers == ModifierKeys.Control)
        {
            ToggleLineComments();
            e.Handled = true;
        }
    }

    private void ToggleLineComments()
    {
        var text = ScriptInput.Text;
        var selStart = ScriptInput.SelectionStart;
        var selLength = ScriptInput.SelectionLength;

        var lineStartIndex = text.LastIndexOf('\n', Math.Max(selStart - 1, 0));
        lineStartIndex = lineStartIndex < 0 ? 0 : lineStartIndex + 1;

        var selEnd = selStart + selLength;
        var lineEndIndex = text.IndexOf('\n', Math.Max(selEnd - 1, lineStartIndex));
        if (lineEndIndex < 0) lineEndIndex = text.Length;

        var block = text.Substring(lineStartIndex, lineEndIndex - lineStartIndex);
        var lines = block.Split('\n');

        var nonEmptyLines = lines.Where(l => l.TrimStart().Length > 0).ToArray();
        bool allCommented = nonEmptyLines.Length > 0 &&
                            nonEmptyLines.All(l => l.TrimStart().StartsWith("//"));

        string[] newLines;
        if (allCommented)
        {
            newLines = lines.Select(l =>
            {
                var trimmed = l.TrimStart();
                if (!trimmed.StartsWith("//")) return l;
                var indent = l.Substring(0, l.Length - trimmed.Length);
                var rest = trimmed.Substring(2);
                if (rest.StartsWith(" ")) rest = rest.Substring(1);
                return indent + rest;
            }).ToArray();
        }
        else
        {
            newLines = lines.Select(l =>
            {
                if (l.TrimStart().Length == 0) return l;
                var indent = l.Substring(0, l.Length - l.TrimStart().Length);
                return indent + "// " + l.TrimStart();
            }).ToArray();
        }

        var newBlock = string.Join('\n', newLines);
        var newText = text.Substring(0, lineStartIndex) + newBlock + text.Substring(lineEndIndex);

        ScriptInput.Text = newText;
        var newBlockEnd = lineStartIndex + newBlock.Length;
        ScriptInput.SelectionStart = lineStartIndex;
        ScriptInput.SelectionLength = newBlockEnd - lineStartIndex;
    }

    private async Task RunCurrentScriptAsync()
    {
        if (_scriptEngine == null || _automationContext == null)
        {
            LogToOutput("[Error] Script engine not initialized. Wait for browser to finish loading.");
            return;
        }

        if (_playRun != null || _scriptConsoleRun != null) return;

        var code = ScriptInput.Text;
        if (string.IsNullOrWhiteSpace(code)) return;

        if (_recorder.IsRecording)
            _recorder.RecordScriptBlock(code);

        _scriptConsoleRun = new ScriptRunControl();
        SetScriptConsoleRunUiRunning();
        ClearOutput();
        StatusText.Text = "Running script...";

        _automationContext.Assert.Reset();
        _lawService.BeginScriptLawSession();

        try
        {
            var result = await ExecuteScriptOffUiThreadAsync(code, _scriptConsoleRun);

            if (result.IsCancelled)
            {
                LogColoredToOutput($"[Cancelled] Script stopped by user ({result.ElapsedMs}ms)", "#CCA700");
                StatusText.Text = $"Script cancelled after {result.ElapsedMs}ms";
            }
            else if (result.Success)
            {
                if (result.ReturnValue != null)
                    LogColoredToOutput($"[Result] {result.ReturnValue}", "#DCDCAA");

                if (_automationContext.Assert.TotalCount > 0)
                    _automationContext.Assert.Summary();

                StatusText.Text = $"Script completed in {result.ElapsedMs}ms";

                if (_automationContext.Assert.TotalCount > 0)
                {
                    StatusText.Text += _automationContext.Assert.AllPassed
                        ? $" | ALL {_automationContext.Assert.PassCount} PASSED"
                        : $" | {_automationContext.Assert.FailCount} FAILED";
                }
            }
            else
            {
                LogColoredToOutput($"[Error] {result.Error}", "#F44747");
                StatusText.Text = "Script failed";
            }
        }
        catch (Exception ex)
        {
            LogColoredToOutput($"[Error] {ex.Message}", "#F44747");
            StatusText.Text = "Script failed";
        }
        finally
        {
            _automationContext?.Laws?.EndScriptLawSession();

            // Capture script output to session log
            if (_sessionLogger.IsLogging)
                CaptureScriptOutputToSessionLog();

            _scriptConsoleRun.Dispose();
            _scriptConsoleRun = null;
            SetScriptConsoleRunUiIdle();

            if (_securityShadow.Config.RunHeavyAfterQuicktest
                && _securityShadow.Enabled
                && _securityShadow.Config.LawsEnabled)
            {
                var heavyReport = await _lawService.RunShadowHeavyAsync();
                LogColoredToOutput($"[Shadow Heavy] {heavyReport.SummaryLine}",
                    heavyReport.LawFailures > 0 ? "#F44747" : "#888888");
            }
        }
    }

    private void LogToOutput(string message)
    {
        LogColoredToOutput(message, "#6A9955");
    }

    private void LogColoredToOutput(string message, string hexColor)
    {
        if (App.CliMode != null)
            CliWriteLine(message);

        Dispatcher.Invoke(() =>
        {
            var paragraph = ScriptOutput.Document.Blocks.LastBlock as Paragraph;
            if (paragraph == null)
            {
                paragraph = new Paragraph { Margin = new Thickness(0) };
                ScriptOutput.Document.Blocks.Add(paragraph);
            }

            if (paragraph.Inlines.Count > 0)
                paragraph.Inlines.Add(new LineBreak());

            var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hexColor)!;
            var run = new Run(message) { Foreground = brush };
            paragraph.Inlines.Add(run);

            ScriptOutput.ScrollToEnd();
        });
    }

    private void ClearOutput()
    {
        Dispatcher.Invoke(() => ScriptOutput.Document.Blocks.Clear());
    }

    private void SetupScriptOutputContextMenu()
    {
        var menu = new ContextMenu();
        var copyItem = new MenuItem { Header = "Copy", InputGestureText = "Ctrl+C" };
        copyItem.Click += (_, _) => ScriptOutput.Copy();
        menu.Items.Add(copyItem);
        var selectAllItem = new MenuItem { Header = "Select All", InputGestureText = "Ctrl+A" };
        selectAllItem.Click += (_, _) => ScriptOutput.SelectAll();
        menu.Items.Add(selectAllItem);
        menu.Items.Add(new Separator());
        var showHtmlItem = new MenuItem { Header = "Show as HTML" };
        showHtmlItem.Click += ShowScriptOutputAsHtml_Click;
        menu.Items.Add(showHtmlItem);
        ScriptOutput.ContextMenu = menu;
    }

    private async void ShowScriptOutputAsHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_automationContext == null || !_isWebViewReady) return;

        var html = GenerateScriptOutputHtml();
        if (html == null) return;

        await OpenHtmlInTabAsync(html, "trowser://test-results");
    }

    private string? GenerateScriptOutputHtml()
    {
        var content = new StringBuilder();

        foreach (var block in ScriptOutput.Document.Blocks)
        {
            if (block is not Paragraph paragraph) continue;

            foreach (var inline in paragraph.Inlines)
            {
                if (inline is Run run)
                {
                    var brush = run.Foreground as SolidColorBrush;
                    var color = brush?.Color ?? Colors.Gray;
                    var hex = $"#{color.R:X2}{color.G:X2}{color.B:X2}";
                    var lightHex = MapToLightThemeColor(hex);
                    var encoded = HtmlExportText.Encode(run.Text);
                    if (string.IsNullOrEmpty(encoded))
                        content.Append("<br>");
                    else
                        content.Append($"<span style=\"color:{lightHex}\">{encoded}</span>");
                }
                else if (inline is LineBreak)
                {
                    content.Append("<br>");
                }
            }
        }

        if (content.Length == 0) return null;

        var pageUrl = "";
        try { pageUrl = _automationContext?.ActiveTab?.WebView?.Source?.ToString() ?? ""; }
        catch (Exception ex) { TrowserLog.Warn($"Could not get page URL for HTML export: {ex.Message}"); }
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        var encodedUrl = HtmlExportText.Encode(pageUrl);
        var urlLine = string.IsNullOrEmpty(pageUrl) || pageUrl == "about:blank"
            ? "" : $"Page: {encodedUrl}<br>";

        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
            "<title>Trowser \u2014 Test Results</title>\n<style>\n" +
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #ffffff; color: #333; }\n" +
            ".page { max-width: 900px; margin: 0 auto; padding: 40px 32px 60px; }\n" +
            ".header { border-bottom: 3px solid #007ACC; padding-bottom: 16px; margin-bottom: 28px; }\n" +
            ".header h1 { font-size: 26px; font-weight: 600; color: #1a1a1a; margin-bottom: 6px; }\n" +
            ".header .meta { font-size: 13px; color: #666; line-height: 1.5; }\n" +
            ".output { font-family: 'Cascadia Code', Consolas, 'Courier New', monospace; font-size: 13px; " +
            "line-height: 1.8; background: #fafbfc; border: 1px solid #d0d7de; border-radius: 8px; " +
            "padding: 20px 24px; white-space: pre-wrap; word-wrap: break-word; }\n" +
            "@media print { .page { padding: 20px 0; } .output { border: 1px solid #ccc; } }\n" +
            "</style>\n</head>\n<body>\n<div class=\"page\">\n" +
            "<div class=\"header\">\n<h1>Trowser \u2014 Test Results</h1>\n" +
            $"<div class=\"meta\">{urlLine}Generated: {timestamp}</div>\n</div>\n" +
            $"<div class=\"output\">{content}</div>\n" +
            "</div>\n</body>\n</html>";
    }

    private static string MapToLightThemeColor(string hexColor)
    {
        return hexColor.ToUpperInvariant() switch
        {
            "#6A9955" => "#1B5E20",
            "#4EC9B0" => "#00796B",
            "#F44747" => "#B71C1C",
            "#DCDCAA" => "#7B6800",
            "#CCA700" => "#E65100",
            "#569CD6" => "#1565C0",
            "#666666" => "#9E9E9E",
            "#CCCCCC" => "#616161",
            "#CE9178" => "#BF360C",
            "#D4D4D4" => "#424242",
            _ => EnsureReadableOnWhite(hexColor)
        };
    }

    private static string EnsureReadableOnWhite(string hexColor)
    {
        if (hexColor.Length != 7 || !hexColor.StartsWith('#')) return "#333333";
        try
        {
            int r = Convert.ToInt32(hexColor.Substring(1, 2), 16);
            int g = Convert.ToInt32(hexColor.Substring(3, 2), 16);
            int b = Convert.ToInt32(hexColor.Substring(5, 2), 16);
            double luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
            if (luminance > 0.55)
            {
                r = (int)(r * 0.5);
                g = (int)(g * 0.5);
                b = (int)(b * 0.5);
                return $"#{r:X2}{g:X2}{b:X2}";
            }
            return hexColor;
        }
        catch (Exception ex) { TrowserLog.Warn($"Color conversion failed for {hexColor}: {ex.Message}"); return "#333333"; }
    }

    private async void ScriptHelp_Click(object sender, RoutedEventArgs e)
    {
        if (_automationContext == null || !_isWebViewReady) return;

        var html = LoadEmbeddedResource("Trowser.Resources.script-help.html");
        await _automationContext.NewTab(null);
        _automationContext.ActiveTab.DisplayUrlOverride = "trowser://script-help";
        ActiveWebView?.CoreWebView2?.NavigateToString(html);
    }

    private void LoadScript_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "C# Script Files (*.csx)|*.csx|All Files (*.*)|*.*",
            DefaultExt = ".csx",
            Title = "Load Script"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                ScriptInput.Text = File.ReadAllText(dialog.FileName);
                StatusText.Text = $"Loaded: {dialog.FileName}";
            }
            catch (Exception ex)
            {
                LogToOutput($"[Error] Failed to load file: {ex.Message}");
            }
        }
    }

    private void SaveScript_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "C# Script Files (*.csx)|*.csx|All Files (*.*)|*.*",
            DefaultExt = ".csx",
            Title = "Save Script"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                File.WriteAllText(dialog.FileName, ScriptInput.Text);
                StatusText.Text = $"Saved: {dialog.FileName}";
            }
            catch (Exception ex)
            {
                LogToOutput($"[Error] Failed to save file: {ex.Message}");
            }
        }
    }

    #region Quicktests

    private static readonly object QuicktestFolderMenuTag = new();

    private readonly ContextMenu _quickTestsMenu = new();

    /// <summary>The "UserScripts" submenu, rebuilt from the user quicktests folder each time the menu opens.</summary>
    private MenuItem? _userScriptsMenu;

    /// <summary>Marks a menu item whose <c>Tag</c> is a user-authored quicktest loaded from disk (not an embedded resource).</summary>
    private sealed record UserQuicktestFile(string Path);

    private void PopulateQuickTests()
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string prefix = "Trowser.Resources.Quicktests.";

        var scripts = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix) && n.EndsWith(".csx"))
            .OrderBy(n => n)
            .ToList();

        _quickTestsMenu.Items.Clear();

        foreach (var resourceName in scripts)
        {
            var relative = resourceName[prefix.Length..^4];
            var parts = relative.Split('.');
            var container = _quickTestsMenu.Items;

            for (var i = 0; i < parts.Length - 1; i++)
            {
                var folder = FormatQuicktestFolderName(parts[i]);
                MenuItem? sub = null;
                foreach (var obj in container)
                {
                    if (obj is MenuItem mi &&
                        folder.Equals(mi.Header as string, StringComparison.Ordinal) &&
                        ReferenceEquals(mi.Tag, QuicktestFolderMenuTag))
                    {
                        sub = mi;
                        break;
                    }
                }

                if (sub == null)
                {
                    sub = new MenuItem { Header = folder, Tag = QuicktestFolderMenuTag };
                    container.Add(sub);
                }

                container = sub.Items;
            }

            var leafName = parts[^1];
            var item = new MenuItem { Header = leafName, Tag = resourceName };
            item.Click += QuickTestMenuItem_Click;
            container.Add(item);
        }

        _userScriptsMenu = new MenuItem { Header = "UserScripts", Tag = QuicktestFolderMenuTag };
        _quickTestsMenu.Items.Add(new Separator());
        _quickTestsMenu.Items.Add(_userScriptsMenu);
    }

    private static string FormatQuicktestFolderName(string name)
    {
        if (string.Equals(name, "TrowserTwelve", StringComparison.Ordinal))
            return "Trowser Twelve";
        return name;
    }

    private void QuickTests_Click(object sender, RoutedEventArgs e)
    {
        RefreshUserQuicktests();
        _quickTestsMenu.PlacementTarget = QuickTestsButton;
        _quickTestsMenu.Placement = PlacementMode.Bottom;
        _quickTestsMenu.IsOpen = true;
    }

    private void QuickTestMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem item) return;

        if (item.Tag is UserQuicktestFile userFile)
        {
            try
            {
                ScriptInput.Text = File.ReadAllText(userFile.Path);
                StatusText.Text = $"Loaded: {userFile.Path}";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Could not read quicktest: {ex.Message}";
                TrowserLog.Warn($"Reading user quicktest failed: {ex.Message}");
            }
            return;
        }

        var resourceName = (string)item.Tag;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null) return;
        using var reader = new StreamReader(stream);
        ScriptInput.Text = reader.ReadToEnd();
    }

    #region User-authored quicktests

    /// <summary>
    /// Folder where technical testers drop their own <c>.csx</c> quicktests. They appear under the
    /// "UserScripts" submenu of the Quicktests button, rescanned each time the menu opens.
    /// </summary>
    private static string UserQuicktestsFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        "Trowser Quicktests");

    /// <summary>Creates the user quicktests folder on first use and seeds it with an example + authoring doc.</summary>
    private static string EnsureUserQuicktestsFolder()
    {
        var dir = UserQuicktestsFolder;
        var fresh = !Directory.Exists(dir);
        Directory.CreateDirectory(dir);
        if (fresh)
            SeedUserQuicktestsFolder(dir);
        return dir;
    }

    private static void SeedUserQuicktestsFolder(string dir)
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            WriteSeedResource(assembly, "Trowser.Resources.UserQuicktests.README.md", Path.Combine(dir, "README.md"));
            WriteSeedResource(assembly, "Trowser.Resources.UserQuicktests.ExampleQuicktest.csx", Path.Combine(dir, "ExampleQuicktest.csx"));
        }
        catch (Exception ex) { TrowserLog.Warn($"Seeding user quicktests folder failed: {ex.Message}"); }
    }

    private static void WriteSeedResource(Assembly assembly, string resourceName, string destPath)
    {
        if (File.Exists(destPath)) return;
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            TrowserLog.Warn($"Seed resource not found: {resourceName}");
            return;
        }
        using var reader = new StreamReader(stream);
        File.WriteAllText(destPath, reader.ReadToEnd());
    }

    /// <summary>Rebuilds the "UserScripts" submenu from the user quicktests folder.</summary>
    private void RefreshUserQuicktests()
    {
        if (_userScriptsMenu == null) return;
        _userScriptsMenu.Items.Clear();

        string folder;
        try
        {
            folder = EnsureUserQuicktestsFolder();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"User quicktests folder unavailable: {ex.Message}");
            _userScriptsMenu.Items.Add(new MenuItem { Header = "(folder unavailable)", IsEnabled = false });
            return;
        }

        _userScriptsMenu.ToolTip = folder;

        var found = PopulateUserQuicktestsInto(_userScriptsMenu.Items, folder);
        if (!found)
            _userScriptsMenu.Items.Add(new MenuItem { Header = "(drop .csx files here)", IsEnabled = false });

        _userScriptsMenu.Items.Add(new Separator());
        var openItem = new MenuItem { Header = "Open folder\u2026" };
        openItem.Click += (_, _) => OpenUserQuicktestsFolder(folder);
        _userScriptsMenu.Items.Add(openItem);
    }

    /// <summary>Recursively mirrors a user quicktests directory into a menu; returns true if any script was added.</summary>
    private bool PopulateUserQuicktestsInto(ItemCollection container, string dir)
    {
        var any = false;
        try
        {
            foreach (var sub in Directory.GetDirectories(dir).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                var subMenu = new MenuItem { Header = Path.GetFileName(sub), Tag = QuicktestFolderMenuTag };
                if (PopulateUserQuicktestsInto(subMenu.Items, sub))
                {
                    container.Add(subMenu);
                    any = true;
                }
            }

            foreach (var file in Directory.GetFiles(dir, "*.csx").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                var item = new MenuItem
                {
                    Header = Path.GetFileNameWithoutExtension(file),
                    Tag = new UserQuicktestFile(file),
                    ToolTip = file
                };
                item.Click += QuickTestMenuItem_Click;
                container.Add(item);
                any = true;
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"Enumerating user quicktests failed: {ex.Message}"); }
        return any;
    }

    private void OpenUserQuicktestsFolder(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            Process.Start(new ProcessStartInfo { FileName = folder, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Could not open folder: {ex.Message}";
            TrowserLog.Warn($"Opening user quicktests folder failed: {ex.Message}");
        }
    }

    #endregion

    /// <summary>
    /// Load an embedded quicktest into the script editor and run it immediately, with an optional
    /// right-click target set as <see cref="AutomationContext.This"/>. Used by context-menu quicktests
    /// such as "Attack this form".
    /// </summary>
    private void RunQuicktestWithTarget(string resourceName, string? thisSelector)
    {
        if (_playRun != null || _scriptConsoleRun != null)
        {
            StatusText.Text = "A script is already running.";
            return;
        }

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            StatusText.Text = $"Quicktest not found: {resourceName}";
            return;
        }
        using var reader = new StreamReader(stream);
        ScriptInput.Text = reader.ReadToEnd();

        IsScriptPanelVisible = true;
        if (_automationContext != null)
            _automationContext.This = string.IsNullOrWhiteSpace(thisSelector) ? null : thisSelector;

        _ = RunCurrentScriptAsync();
    }

    #endregion

    #endregion
}
