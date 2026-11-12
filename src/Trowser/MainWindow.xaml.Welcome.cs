using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Trowser.Automation;

namespace Trowser;

public partial class MainWindow
{
    #region Welcome page actions

    /// <summary>
    /// Embedded in the welcome page and required on every <c>__trowser_welcome</c> message, so an
    /// arbitrary site cannot postMessage its way into running quicktests or opening panels.
    /// </summary>
    private static readonly string WelcomeToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private const string WelcomeAskAiPrompt =
        "Look at this site and help me understand what is important to test. " +
        "Who are the users and what do they want to achieve? Which relations (features, data, integrations, business) " +
        "and risks matter most? Suggest a handful of diverse test ideas, starting with the most important.";

    private async void HandleWelcomeMessage(BrowserTab tab, JsonElement root)
    {
        if (!IsActiveTab(tab)) return;
        if (!root.TryGetProperty("token", out var tokenProp) || tokenProp.GetString() != WelcomeToken) return;

        var action = root.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
        var url = root.TryGetProperty("url", out var u) ? u.GetString()?.Trim() : null;
        var quicktest = root.TryGetProperty("quicktest", out var q) ? q.GetString() : null;

        try
        {
            switch (action)
            {
                case "open":
                    if (!string.IsNullOrEmpty(url))
                        await OpenWelcomeTargetInNewTabAsync(url);
                    break;

                case "explore":
                    EnsureSessionLoggingStarted(force: true);
                    IsJournalPanelVisible = true;
                    if (!string.IsNullOrEmpty(url))
                        await OpenWelcomeTargetInNewTabAsync(url);
                    break;

                case "ask-ai":
                    if (!await OpenWelcomeTargetInNewTabAsync(url)) return;
                    IsChatPanelVisible = true;
                    ChatPanelControl.PrefillInput(WelcomeAskAiPrompt);
                    break;

                case "inspiration":
                    ShowInspirationOverlay();
                    break;

                case "test-data":
                    await CopyRandomTestDataAsync();
                    break;

                case "quicktest":
                    await RunWelcomeQuicktestAsync(quicktest, url);
                    break;

                case "quicktests-menu":
                    IsScriptPanelVisible = true;
                    _ = Dispatcher.InvokeAsync(() => QuickTests_Click(QuickTestsButton, new RoutedEventArgs()),
                        DispatcherPriority.Loaded);
                    break;

                case "note":
                    ShowNoteOverlay();
                    break;

                case "strange-moment":
                    if (!await OpenWelcomeTargetInNewTabAsync(url)) return;
                    OpenStrangeMoment();
                    break;

                case "journal-report":
                    await OpenJournalReportInTabAsync();
                    break;

                case "record":
                    if (!await OpenWelcomeTargetInNewTabAsync(url)) return;
                    StartRecording();
                    break;

                case "script-console":
                    IsScriptPanelVisible = true;
                    ScriptInput.Focus();
                    break;

                case "api":
                    if (_apiServer?.IsRunning != true)
                    {
                        _apiUserWantsServerRunning = true;
                        ToggleApiOn();
                        SaveApiUserSettings();
                    }
                    StatusText.Text = $"API running on http://localhost:{_apiPort} (MCP at /mcp) - give your agent the trowserkit folder";
                    break;

                case "manual":
                    await OpenIntroductionInNewTabAsync();
                    break;
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Welcome action failed: {ex.Message}";
            TrowserLog.Warn($"Welcome action '{action}' failed: {ex.Message}");
        }
    }

    private async Task RunWelcomeQuicktestAsync(string? quicktest, string? url)
    {
        if (_playRun != null || _scriptConsoleRun != null)
        {
            StatusText.Text = "A script is already running.";
            return;
        }
        if (string.IsNullOrWhiteSpace(quicktest) || ResolveQuicktestResourceName(quicktest) == null)
        {
            StatusText.Text = $"Quicktest not found: {quicktest}";
            return;
        }
        if (!await OpenWelcomeTargetInNewTabAsync(url)) return;
        OnQuicktestRequested(quicktest);
    }

    private async Task OpenIntroductionInNewTabAsync()
    {
        if (_automationContext == null || !_isWebViewReady) return;

        var html = LoadEmbeddedResource("Trowser.Resources.introduction.html");
        var iconBase64 = LoadEmbeddedResourceBase64("Trowser.Resources.trowser.png");
        html = html.Replace("{{ICON_BASE64}}", iconBase64);
        await OpenHtmlInTabAsync(html, "trowser://introduction");
    }

    /// <summary>
    /// Open the address from the welcome page in a new tab (welcome stays open in its tab).
    /// Follow-up actions run on the new active tab after <see cref="AutomationContext.NewTab"/>.
    /// Returns false if scope blocks the URL or tab creation fails.
    /// </summary>
    private async Task<bool> OpenWelcomeTargetInNewTabAsync(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return true;
        if (_automationContext == null) return false;

        var normalized = NormalizeUrl(input.Trim());
        if (!_navigationGuard.IsAllowed(normalized))
        {
            StatusText.Text = $"Blocked: {normalized} is outside the navigation scope";
            return false;
        }

        try
        {
            await _automationContext.NewTab(input.Trim(), TabOwners.Human);
            UpdateActiveTabVisibility();
            UpdateNavigationUI();
            return true;
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to open tab: {ex.Message}";
            TrowserLog.Warn($"Welcome new-tab open failed: {ex.Message}");
            return false;
        }
    }

    #endregion
}
