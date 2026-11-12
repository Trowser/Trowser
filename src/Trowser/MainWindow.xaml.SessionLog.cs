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
using Trowser.Recording;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region Session Log

    /// <summary>
    /// Keep Tab / Shift+Tab inside the web page (CDP) instead of moving WPF focus to chrome controls.
    /// Script console keeps native Tab for indentation (AcceptsTab).
    /// </summary>
    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Tab || e.Handled)
            return;

        var mods = Keyboard.Modifiers;
        if (mods.HasFlag(ModifierKeys.Control) || mods.HasFlag(ModifierKeys.Alt))
            return;

        if (Keyboard.FocusedElement is TextBox { AcceptsTab: true })
            return;

        // Address bar uses Tab to accept a completion; don't send it into the page.
        if (ReferenceEquals(Keyboard.FocusedElement, AddressBar))
            return;

        if (_automationContext == null || !_isWebViewReady || ActiveWebView?.CoreWebView2 == null)
            return;

        e.Handled = true;
        var shift = mods.HasFlag(ModifierKeys.Shift);
        _ = _automationContext.DispatchRealTabKeyAsync(shift);
    }

    /// <summary>
    /// Intercept keys on the WebView2 control before it consumes browser accelerators
    /// (e.g. Ctrl+N = new window). Marks them as handled so they don't reach WebView2.
    /// </summary>
    private void Tab_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        // Ctrl+Shift+T — tester note
        if (e.Key == Key.T && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            ShowNoteOverlay();
            e.Handled = true;
        }

        // Ctrl+Shift+S — screenshot to session log
        if (e.Key == Key.S && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            if (_sessionLogger.IsLogging)
            {
                _ = TakeSessionScreenshotAsync();
                e.Handled = true;
            }
        }

        // Ctrl+Shift+R — HTTP Request Editor
        if (e.Key == Key.R && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            RequestEditorButton_Click(sender, e);
            e.Handled = true;
        }

        // Ctrl+D — random test data to clipboard
        if (e.Key == Key.D && Keyboard.Modifiers == ModifierKeys.Control)
        {
            _ = CopyRandomTestDataAsync();
            e.Handled = true;
        }

        // Ctrl+I — testing inspiration
        if (e.Key == Key.I && Keyboard.Modifiers == ModifierKeys.Control)
        {
            ShowInspirationOverlay();
            e.Handled = true;
        }

        // Ctrl+B — screen curtain (blind testing mode)
        if (e.Key == Key.B && Keyboard.Modifiers == ModifierKeys.Control)
        {
            _ = ToggleScreenCurtainFromUiAsync();
            e.Handled = true;
        }

        // Ctrl+J — toggle the left-docked Journal panel (intercept before WebView2 consumes it)
        if (e.Key == Key.J && Keyboard.Modifiers == ModifierKeys.Control)
        {
            IsJournalPanelVisible = !IsJournalPanelVisible;
            e.Handled = true;
        }

        // Ctrl+Shift+L — interesting moment (intercept before WebView2 consumes it)
        if (e.Key == Key.L && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            OpenStrangeMoment();
            e.Handled = true;
        }

        // Ctrl+Shift+P — toggle the agent pointer overlay
        if (e.Key == Key.P && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            TogglePointerOverlay();
            e.Handled = true;
        }

        // F12 — open DevTools (WebView2 would consume this otherwise, and we would not
        // know to open DevTools on the next tab before it navigates).
        if (e.Key == Key.F12)
        {
            OpenDevToolsFromUi();
            e.Handled = true;
        }

        // Ctrl+Shift+C — WebView2 Inspect element. Let it through, but remember DevTools
        // is in use so a page-opened tab gets DevTools from the first request.
        if (e.Key == Key.C && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
            _followDevToolsOnNewTabs = true;
    }

    private async Task ToggleScreenCurtainFromUiAsync()
    {
        if (_automationContext == null) return;
        try
        {
            var enabled = await _automationContext.ToggleScreenCurtain();
            StatusText.Text = enabled
                ? "Screen curtain ON — use a screen reader (Ctrl+B to toggle)"
                : "Screen curtain OFF";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Screen curtain error: {ex.Message}";
        }
    }

    private void LogStatus_Click(object sender, MouseButtonEventArgs e)
    {
        OpenSessionLogDialog();
    }

    private void NoteButton_Click(object sender, RoutedEventArgs e)
    {
        ShowNoteOverlay();
    }

    private void SessionLogMenu_Click(object sender, RoutedEventArgs e)
    {
        OpenSessionLogDialog();
    }

    private void OpenSessionLogDialog()
    {
        var dialog = new SessionLogDialog(this, _sessionLogger, _sessionLogSettings, UpdateLogStatusDisplay,
            () => _automationContext?.ActiveTab?.WebView?.CoreWebView2?.Source);
        dialog.ShowDialog();
    }

    private void UpdateLogStatusDisplay()
    {
        Dispatcher.Invoke(() =>
        {
            if (_sessionLogger.IsLogging)
            {
                LogStatusText.Text = "Log:On";
                LogStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4EC9B0"));
                ((Border)LogStatusText.Parent).ToolTip =
                    $"Session logging active\nFile: {Path.GetFileName(_sessionLogger.FilePath)}\n\nCtrl+Shift+S — Screenshot\n\nClick to open settings";

                // Inject recording script into current tab for action capture
                var activeTab = _automationContext?.ActiveTab;
                if (activeTab != null)
                    _ = InjectRecordingScriptAsync(activeTab);
            }
            else
            {
                LogStatusText.Text = "Log:Off";
                LogStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF9552"));
                ((Border)LogStatusText.Parent).ToolTip = "Click to open session log settings";
            }

            JournalPanelControl.UpdateRecordingState();
        });
    }

    private NoteOverlay? _noteOverlay;

    private void ShowNoteOverlay(SessionLogger.JournalEntry? edit = null)
    {
        if (_noteOverlay != null && _noteOverlay.IsLoaded && edit == null) return;

        try
        {
            if (_noteOverlay != null)
            {
                try { _noteOverlay.Close(); } catch { /* already closing */ }
                _noteOverlay = null;
            }

            StatusText.Text = edit == null ? "Opening note overlay..." : "Editing journal entry...";
            _noteOverlay = new NoteOverlay(this, _sessionLogger, () =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = _sessionLogger.IsLogging ? "Note saved" : "Ready";
                    _noteOverlay = null;
                });
            }, edit);
            _noteOverlay.Show();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Note overlay failed: {ex.Message}";
            TrowserLog.Error("Note overlay failed", ex);
            _noteOverlay = null;
        }
    }

    private MessageOverlay? _messageOverlay;

    // --- Message history (always stored, independent of session logging) ---
    public record StoredMessage(string Text, string Level, int DurationMs, DateTime Timestamp, string? CopyText = null)
    {
        public string TextToCopy => string.IsNullOrWhiteSpace(CopyText) ? Text : CopyText;
    }
    private readonly List<StoredMessage> _messageHistory = new();
    private int _unreadMessageCount;
    private MessageBrowserOverlay? _messageBrowserOverlay;

    private void ShowApiMessage(string text, string level, int durationMs, string? copyText = null)
    {
        // Log to session if active
        if (_sessionLogger.IsLogging)
            _sessionLogger.LogMessage(text, level);

        // Store in history (always, regardless of session logging)
        _messageHistory.Add(new StoredMessage(text, level.ToLowerInvariant(), durationMs, DateTime.Now, copyText));
        _unreadMessageCount++;
        UpdateMessageIcon();

        // Dismiss any existing message overlay
        try { _messageOverlay?.Dismiss(); } catch { /* already closed */ }

        try
        {
            var messageLevel = level.ToLowerInvariant() switch
            {
                "warning" => MessageOverlay.MessageLevel.Warning,
                "error"   => MessageOverlay.MessageLevel.Error,
                _         => MessageOverlay.MessageLevel.Info
            };

            _messageOverlay = new MessageOverlay(this, text, messageLevel, durationMs, copyText);
            _messageOverlay.Closed += (_, _) =>
            {
                if (_messageOverlay?.IsLoaded == false)
                    _messageOverlay = null;
            };
            _messageOverlay.Show();
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Message overlay failed", ex);
            _messageOverlay = null;
        }
    }

    private void UpdateMessageIcon()
    {
        if (_messageHistory.Count == 0)
        {
            MessageIconText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888888"));
            MessageBadge.Visibility = Visibility.Collapsed;
        }
        else
        {
            MessageIconText.Foreground = new SolidColorBrush(Colors.White);
            if (_unreadMessageCount > 0)
            {
                MessageBadge.Visibility = Visibility.Visible;
                MessageBadgeCount.Text = _unreadMessageCount > 99 ? "99+" : _unreadMessageCount.ToString();
            }
            else
            {
                MessageBadge.Visibility = Visibility.Collapsed;
            }
        }
    }

    /// <summary>Message icon: opens the history overlay when there are stored toasts; no-op if empty (badge hidden).</summary>
    private void MessageIcon_Click(object sender, MouseButtonEventArgs e)
    {
        if (_messageHistory.Count == 0) return;

        _unreadMessageCount = 0;
        UpdateMessageIcon();

        // Dismiss any existing browser overlay
        try { _messageBrowserOverlay?.Close(); } catch { /* already closed */ }

        var overlay = new MessageBrowserOverlay(this, _messageHistory);
        _messageBrowserOverlay = overlay;
        overlay.Closed += (_, _) =>
        {
            if (ReferenceEquals(_messageBrowserOverlay, overlay))
                _messageBrowserOverlay = null;
        };
        overlay.Show();
    }

    private async Task TakeSessionScreenshotAsync()
    {
        if (_automationContext == null || !_sessionLogger.IsLogging || _sessionLogger.FilePath == null) return;

        try
        {
            var logDir = Path.GetDirectoryName(Path.GetFullPath(_sessionLogger.FilePath))!;
            var screenshotDir = Path.Combine(logDir, "screenshots");
            Directory.CreateDirectory(screenshotDir);

            var fileName = $"{DateTime.Now:yyyyMMdd_HHmmss}.png";
            var filePath = Path.Combine(screenshotDir, fileName);

            var bytes = await _automationContext.ScreenshotToBytes();
            await File.WriteAllBytesAsync(filePath, bytes);

            _sessionLogger.LogScreenshot(filePath);
            StatusText.Text = $"Screenshot saved: {fileName}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Screenshot failed: {ex.Message}";
            TrowserLog.Error("Session screenshot failed", ex);
        }
    }

    /// <summary>
    /// Transform a recorded browser action (from the JS injection) into a REST API log entry.
    /// </summary>
    private void LogRecordedActionToSession(System.Text.Json.JsonElement action)
    {
        try
        {
            var type = action.GetProperty("type").GetString();
            if (!CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Journal, type))
                return;

            string apiPath;
            string? jsonBody;
            string? description;

            switch (type)
            {
                case "click":
                    apiPath = "/api/click";
                    (jsonBody, description) = BuildActionJson(action, "click");
                    break;
                case "type":
                    apiPath = "/api/type";
                    (jsonBody, description) = BuildTypeJson(action);
                    break;
                case "select":
                    apiPath = "/api/select";
                    (jsonBody, description) = BuildSelectJson(action);
                    break;
                case "hover":
                    apiPath = "/api/hover";
                    (jsonBody, description) = BuildActionJson(action, "hover");
                    break;
                case "key":
                    apiPath = "/api/key";
                    (jsonBody, description) = BuildKeyJson(action);
                    break;
                case "radio":
                    apiPath = "/api/click";
                    (jsonBody, description) = BuildRadioJson(action);
                    break;
                case "scroll":
                    apiPath = "/api/scroll";
                    (jsonBody, description) = BuildScrollJson(action);
                    break;
                default:
                    return; // assert, elementOfInterest etc. — not browser actions
            }

            _sessionLogger.LogBrowserAction("POST", apiPath, jsonBody, description);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Session log action capture failed: {ex.Message}");
        }
    }

    private static (string json, string? desc) BuildActionJson(System.Text.Json.JsonElement action, string actionType)
    {
        var role = GetActionStr(action, "role");
        var label = GetActionStr(action, "label");
        var text = GetActionStr(action, "text");
        var selector = GetActionStr(action, "selector");
        var testId = GetActionStr(action, "testId");

        var desc = !string.IsNullOrEmpty(role) && !string.IsNullOrEmpty(label)
            ? $"{role} \"{label}\""
            : !string.IsNullOrEmpty(text) && text.Length <= 60
            ? $"\"{text}\""
            : null;

        var body = BuildLocatorJson(testId, role, label, text, selector);
        return (body, desc);
    }

    private static (string json, string? desc) BuildTypeJson(System.Text.Json.JsonElement action)
    {
        var label = GetActionStr(action, "label");
        var placeholder = GetActionStr(action, "placeholder");
        var value = GetActionStr(action, "value");
        var selector = GetActionStr(action, "selector");
        var testId = GetActionStr(action, "testId");
        var inputType = GetActionStr(action, "inputType");

        var displayValue = inputType == "password" ? "***" : value;
        var fieldName = !string.IsNullOrEmpty(label) ? label
            : !string.IsNullOrEmpty(placeholder) ? placeholder : "";
        var desc = !string.IsNullOrEmpty(fieldName) ? $"\"{fieldName}\"" : null;

        var parts = new List<string>();
        if (!string.IsNullOrEmpty(testId)) parts.Add($"\"testId\": \"{JsonEsc(testId)}\"");
        else if (!string.IsNullOrEmpty(label)) parts.Add($"\"label\": \"{JsonEsc(label)}\"");
        else if (!string.IsNullOrEmpty(placeholder)) parts.Add($"\"placeholder\": \"{JsonEsc(placeholder)}\"");
        else if (!string.IsNullOrEmpty(selector)) parts.Add($"\"selector\": \"{JsonEsc(selector)}\"");
        parts.Add($"\"text\": \"{JsonEsc(displayValue)}\"");
        return ("{" + string.Join(", ", parts) + "}", desc);
    }

    private static (string json, string? desc) BuildSelectJson(System.Text.Json.JsonElement action)
    {
        var label = GetActionStr(action, "label");
        var value = GetActionStr(action, "value");
        var selectedText = GetActionStr(action, "selectedText");
        var selector = GetActionStr(action, "selector");
        var testId = GetActionStr(action, "testId");

        var desc = !string.IsNullOrEmpty(label)
            ? $"\"{label}\" → \"{selectedText}\""
            : !string.IsNullOrEmpty(selectedText) ? $"\"{selectedText}\"" : null;

        var parts = new List<string>();
        if (!string.IsNullOrEmpty(testId)) parts.Add($"\"testId\": \"{JsonEsc(testId)}\"");
        else if (!string.IsNullOrEmpty(label)) parts.Add($"\"label\": \"{JsonEsc(label)}\"");
        else if (!string.IsNullOrEmpty(selector)) parts.Add($"\"selector\": \"{JsonEsc(selector)}\"");
        parts.Add($"\"value\": \"{JsonEsc(value)}\"");
        return ("{" + string.Join(", ", parts) + "}", desc);
    }

    private static (string json, string? desc) BuildKeyJson(System.Text.Json.JsonElement action)
    {
        var key = GetActionStr(action, "key");
        var ctrl = GetActionBool(action, "ctrlKey");
        var alt = GetActionBool(action, "altKey");
        var shift = GetActionBool(action, "shiftKey");

        var mods = new List<string>();
        if (ctrl) mods.Add("Ctrl");
        if (alt) mods.Add("Alt");
        if (shift) mods.Add("Shift");

        var desc = mods.Count > 0 ? $"{string.Join("+", mods)}+{key}" : key;
        var json = $"{{\"key\": \"{JsonEsc(key)}\"}}";
        return (json, desc);
    }

    private static (string json, string? desc) BuildScrollJson(System.Text.Json.JsonElement action)
    {
        var x = GetActionNum(action, "scrollX");
        var y = GetActionNum(action, "scrollY");
        var selector = GetActionStr(action, "selector");
        var desc = string.IsNullOrEmpty(selector) ? $"scroll {y:0}" : $"scroll {selector} {y:0}";
        var parts = new List<string>
        {
            $"\"x\": {x.ToString(System.Globalization.CultureInfo.InvariantCulture)}",
            $"\"y\": {y.ToString(System.Globalization.CultureInfo.InvariantCulture)}"
        };
        if (!string.IsNullOrEmpty(selector))
            parts.Add($"\"selector\": \"{JsonEsc(selector)}\"");
        return ("{" + string.Join(", ", parts) + "}", desc);
    }

    private static (string json, string? desc) BuildRadioJson(System.Text.Json.JsonElement action)
    {
        var radioValue = GetActionStr(action, "radioValue");
        var groupLabel = GetActionStr(action, "groupLabel");
        var desc = !string.IsNullOrEmpty(groupLabel) ? $"radio \"{groupLabel}\" → \"{radioValue}\"" : $"radio \"{radioValue}\"";
        return ($"{{\"text\": \"{JsonEsc(radioValue)}\"}}", desc);
    }

    private static string BuildLocatorJson(string? testId, string? role, string? label, string? text, string? selector)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(testId)) parts.Add($"\"testId\": \"{JsonEsc(testId)}\"");
        else if (!string.IsNullOrEmpty(role))
        {
            parts.Add($"\"role\": \"{JsonEsc(role)}\"");
            if (!string.IsNullOrEmpty(label)) parts.Add($"\"label\": \"{JsonEsc(label)}\"");
        }
        else if (!string.IsNullOrEmpty(label)) parts.Add($"\"label\": \"{JsonEsc(label)}\"");
        else if (!string.IsNullOrEmpty(text) && text.Length <= 60) parts.Add($"\"byText\": \"{JsonEsc(text)}\"");
        else if (!string.IsNullOrEmpty(selector)) parts.Add($"\"selector\": \"{JsonEsc(selector)}\"");

        return "{" + string.Join(", ", parts) + "}";
    }

    private static string GetActionStr(System.Text.Json.JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == System.Text.Json.JsonValueKind.String)
            return val.GetString() ?? "";
        return "";
    }

    private static double GetActionNum(System.Text.Json.JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == System.Text.Json.JsonValueKind.Number)
            return val.GetDouble();
        return 0;
    }

    private static bool GetActionBool(System.Text.Json.JsonElement el, string prop)
    {
        return el.TryGetProperty(prop, out var val) && val.ValueKind == System.Text.Json.JsonValueKind.True;
    }

    private static string JsonEsc(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");

    private void CaptureScriptOutputToSessionLog()
    {
        Dispatcher.Invoke(() =>
        {
            try
            {
                var textRange = new TextRange(
                    ScriptOutput.Document.ContentStart,
                    ScriptOutput.Document.ContentEnd);
                var text = textRange.Text.Trim();
                if (!string.IsNullOrEmpty(text))
                    _sessionLogger.LogScriptOutput(text);
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"Session log script output capture failed: {ex.Message}");
            }
        });
    }

    #endregion
}
