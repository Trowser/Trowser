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
    #region CLI Mode

    private async Task RunCliModeAsync(CliOptions options)
    {
        var exitCode = 0;

        try
        {
            var code = await File.ReadAllTextAsync(options.ScriptFile);

            if (!string.IsNullOrEmpty(options.Url))
                await NavigateAndWaitAsync(options.Url);

            _automationContext!.Assert.Reset();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
            var result = await _scriptEngine!.ExecuteAsync(code, cts.Token);

            if (result.IsCancelled)
            {
                CliWriteLine($"[Error] Script timed out after {options.TimeoutSeconds} seconds.");
                exitCode = 2;
            }
            else if (result.Success)
            {
                if (result.ReturnValue != null)
                    CliWriteLine($"[Result] {result.ReturnValue}");

                if (_automationContext.Assert.TotalCount > 0)
                {
                    _automationContext.Assert.Summary();
                    exitCode = _automationContext.Assert.AllPassed ? 0 : 1;
                }

                CliWriteLine($"");
                CliWriteLine($"Script completed in {result.ElapsedMs}ms.");
            }
            else
            {
                CliWriteLine($"[Error] {result.Error}");
                exitCode = 2;
            }
        }
        catch (OperationCanceledException)
        {
            CliWriteLine($"[Error] Script timed out after {options.TimeoutSeconds} seconds.");
            exitCode = 2;
        }
        catch (Exception ex)
        {
            CliWriteLine($"[Error] {ex.Message}");
            exitCode = 2;
        }

        if (!string.IsNullOrEmpty(options.OutputFile))
        {
            try
            {
                var dir = Path.GetDirectoryName(options.OutputFile);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                await File.WriteAllLinesAsync(options.OutputFile, _cliOutputLines, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                System.Console.Error.WriteLine($"Failed to write output file: {ex.Message}");
            }
        }

        ExitCli(exitCode);
    }

    private async Task NavigateAndWaitAsync(string url)
    {
        if (!_isWebViewReady) return;

        url = NormalizeUrl(url);
        var webView = ActiveWebView!;
        var tcs = new TaskCompletionSource<bool>();

        void handler(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            webView.CoreWebView2.NavigationCompleted -= handler;
            tcs.TrySetResult(e.IsSuccess);
        }

        webView.CoreWebView2.NavigationCompleted += handler;
        webView.CoreWebView2.Navigate(url);

        var success = await tcs.Task;
        if (!success)
            CliWriteLine($"[Warning] Navigation to {url} completed with errors.");
    }

    private void CliWriteLine(string line)
    {
        System.Console.WriteLine(line);
        _cliOutputLines.Add(line);
    }

    private void ExitCli(int exitCode)
    {
        Dispatcher.InvokeAsync(() => Application.Current.Shutdown(exitCode));
    }

    #endregion

    #region Navigation

    internal void NavigateTo(string input)
    {
        if (!_isWebViewReady || ActiveWebView == null) return;

        var url = NormalizeUrl(input);

        if (!_navigationGuard.IsAllowed(url))
        {
            StatusText.Text = $"Blocked: {url} is outside the navigation scope";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            return;
        }

        if (_recorder.IsRecording)
        {
            _recorderAddressBarNav = true;
            _recorder.RecordAddressBarNavigation(url);
        }

        if (_mirrorController is { IsActive: true })
            _mirrorController.EnqueueNavigation(url);

        if (_sessionLogger.IsLogging)
        {
            _sessionLogger.LogBrowserAction("POST", "/api/navigate",
                $"{{\"url\": \"{url.Replace("\"", "\\\"")}\"}}", null);
        }

        _urlCompletion.Record(url);
        HideSuggestions(restoreTyped: false);
        _addressBarProgrammatic = true;
        try
        {
            AddressBar.Text = url;
            _addressBarTyped = url;
        }
        finally
        {
            _addressBarProgrammatic = false;
        }

        try
        {
            ActiveWebView.CoreWebView2.Navigate(url);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Navigation error: {ex.Message}";
        }
    }

    private void NavigateToWelcomePage()
    {
        if (!_isWebViewReady || ActiveWebView == null) return;

        _automationContext?.ActiveTab?.Console.Clear();
        _automationContext?.ActiveTab?.Network.Clear();

        var lastUrl = ActiveWebView.Source?.ToString() ?? "";
        if (!lastUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !lastUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            lastUrl = "";

        var html = LoadEmbeddedResource("Trowser.Resources.welcome.html");
        var iconBase64 = LoadEmbeddedResourceBase64("Trowser.Resources.trowser.png");
        html = html.Replace("{{ICON_BASE64}}", iconBase64)
            .Replace("{{WELCOME_TOKEN}}", WelcomeToken)
            .Replace("{{LAST_URL}}", System.Net.WebUtility.HtmlEncode(lastUrl));
        ActiveWebView.CoreWebView2.NavigateToString(html);
        AddressBar.Text = DisplayUrl(null);
        StatusText.Text = "Ready";
        StatusText.Foreground = new SolidColorBrush(Colors.White);
    }

    private static string LoadEmbeddedResource(string logicalName)
    {
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(logicalName)
            ?? throw new InvalidOperationException($"Embedded resource '{logicalName}' not found.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string LoadEmbeddedResourceBase64(string logicalName)
    {
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(logicalName)
            ?? throw new InvalidOperationException($"Embedded resource '{logicalName}' not found.");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Convert.ToBase64String(ms.ToArray());
    }

    private static string NormalizeUrl(string input)
    {
        input = input.Trim();
        if (Uri.TryCreate(input, UriKind.Absolute, out var uri) &&
            (uri.Scheme == "http" || uri.Scheme == "https" || uri.Scheme == "file"))
        {
            return input;
        }
        if (IsLocalhostAddress(input))
        {
            return "http://" + input;
        }
        if (input.Contains('.') && !input.Contains(' '))
        {
            return "https://" + input;
        }
        return $"https://www.google.com/search?q={Uri.EscapeDataString(input)}";
    }

    /// <summary>
    /// <c>localhost</c> has no dot, so the usual "looks like a host" check would send it to search.
    /// Testers type this constantly; treat it as an address (Chrome does the same).
    /// </summary>
    private static bool IsLocalhostAddress(string input)
    {
        if (input.StartsWith("localhost", StringComparison.OrdinalIgnoreCase))
            return input.Length == 9 || input[9] is ':' or '/';
        return false;
    }

    #endregion

    #region UI Event Handlers

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActiveWebView?.CanGoBack == true)
        {
            ActiveWebView.GoBack();
            if (_sessionLogger.IsLogging)
                _sessionLogger.LogBrowserAction("POST", "/api/go-back", null, null);
        }
    }

    private void ForwardButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActiveWebView?.CanGoForward == true)
        {
            ActiveWebView.GoForward();
            if (_sessionLogger.IsLogging)
                _sessionLogger.LogBrowserAction("POST", "/api/go-forward", null, null);
        }
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isWebViewReady) ActiveWebView?.Reload();
        if (_sessionLogger.IsLogging)
            _sessionLogger.LogBrowserAction("POST", "/api/navigate", "{\"action\": \"reload\"}", null);
    }

    private void StopButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isWebViewReady) ActiveWebView?.CoreWebView2?.Stop();
    }

    private void HomeButton_Click(object sender, RoutedEventArgs e)
    {
        NavigateToWelcomePage();
    }

    private void ScriptToggleButton_Click(object sender, RoutedEventArgs e)
    {
        IsScriptPanelVisible = !IsScriptPanelVisible;
    }

    /// <summary>
    /// Header "x" button: closes the script console the same way as the menu item and
    /// the Ctrl+0 accelerator. A running script keeps running in the background.
    /// </summary>
    private void ScriptCloseButton_Click(object sender, RoutedEventArgs e)
    {
        IsScriptPanelVisible = false;
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        // Alt+Home to go to welcome page
        if (e.Key == Key.Home && Keyboard.Modifiers == ModifierKeys.Alt)
        {
            NavigateToWelcomePage();
            e.Handled = true;
        }

        // Ctrl+T: New tab
        if (e.Key == Key.T && Keyboard.Modifiers == ModifierKeys.Control)
        {
            _ = CreateNewTabFromUIAsync(null);
            e.Handled = true;
        }

        // Ctrl+W: Close current tab
        if (e.Key == Key.W && Keyboard.Modifiers == ModifierKeys.Control)
        {
            if (_automationContext != null && _automationContext.Tabs.Count > 1)
                CloseTabByIndex(_automationContext.GetActiveTabIndex());
            e.Handled = true;
        }

        // Ctrl+Tab: Next tab
        if (e.Key == Key.Tab && Keyboard.Modifiers == ModifierKeys.Control)
        {
            if (_automationContext != null && _automationContext.Tabs.Count > 1)
            {
                var next = (_automationContext.GetActiveTabIndex() + 1) % _automationContext.Tabs.Count;
                _automationContext.SwitchTab(next);
            }
            e.Handled = true;
        }

        // Ctrl+Shift+Tab: Previous tab
        if (e.Key == Key.Tab && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            if (_automationContext != null && _automationContext.Tabs.Count > 1)
            {
                var prev = (_automationContext.GetActiveTabIndex() - 1 + _automationContext.Tabs.Count) % _automationContext.Tabs.Count;
                _automationContext.SwitchTab(prev);
            }
            e.Handled = true;
        }

        // Ctrl+1 through Ctrl+9: Switch to tab N
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key >= Key.D1 && e.Key <= Key.D9)
        {
            var tabIndex = e.Key - Key.D1;
            if (_automationContext != null && tabIndex < _automationContext.Tabs.Count)
                _automationContext.SwitchTab(tabIndex);
            e.Handled = true;
        }

        // Ctrl+Shift+L: interesting moment — open AI Assistant with a prefilled prompt
        if (e.Key == Key.L && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            OpenStrangeMoment();
            e.Handled = true;
        }

        // Ctrl+L to toggle chat panel
        if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control)
        {
            IsChatPanelVisible = !IsChatPanelVisible;
            e.Handled = true;
        }

        // Ctrl+0 to toggle script console
        if (e.Key == Key.D0 && Keyboard.Modifiers == ModifierKeys.Control)
        {
            IsScriptPanelVisible = !IsScriptPanelVisible;
            if (IsScriptPanelVisible) ScriptInput.Focus();
            e.Handled = true;
        }

        // Ctrl+J to toggle the left-docked Journal panel
        if (e.Key == Key.J && Keyboard.Modifiers == ModifierKeys.Control)
        {
            IsJournalPanelVisible = !IsJournalPanelVisible;
            e.Handled = true;
        }

        // Ctrl+Shift+T: Add a tester note
        if (e.Key == Key.T && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            ShowNoteOverlay();
            e.Handled = true;
        }

        // Ctrl+Shift+S: Take screenshot to session log
        if (e.Key == Key.S && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            if (_sessionLogger.IsLogging)
                _ = TakeSessionScreenshotAsync();
            e.Handled = true;
        }

        // Ctrl+Shift+R: Open HTTP Request Editor
        if (e.Key == Key.R && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            RequestEditorButton_Click(sender, e);
            e.Handled = true;
        }

        // Ctrl+D: Copy random test data to clipboard
        if (e.Key == Key.D && Keyboard.Modifiers == ModifierKeys.Control)
        {
            _ = CopyRandomTestDataAsync();
            e.Handled = true;
        }

        // Ctrl+I: Show testing inspiration
        if (e.Key == Key.I && Keyboard.Modifiers == ModifierKeys.Control)
        {
            ShowInspirationOverlay();
            e.Handled = true;
        }

        // Ctrl+B: Toggle screen curtain (blind testing mode)
        if (e.Key == Key.B && Keyboard.Modifiers == ModifierKeys.Control)
        {
            _ = ToggleScreenCurtainFromUiAsync();
            e.Handled = true;
        }

        // F12 to open DevTools (also marks follow-on so new tabs open DevTools before they navigate)
        if (e.Key == Key.F12)
        {
            OpenDevToolsFromUi();
            e.Handled = true;
        }

        // F5 to refresh
        if (e.Key == Key.F5)
        {
            if (_isWebViewReady) ActiveWebView?.Reload();
            e.Handled = true;
        }

        // Alt+Left for back
        if (e.Key == Key.Left && Keyboard.Modifiers == ModifierKeys.Alt)
        {
            if (ActiveWebView?.CanGoBack == true) ActiveWebView.GoBack();
            e.Handled = true;
        }

        // Alt+Right for forward
        if (e.Key == Key.Right && Keyboard.Modifiers == ModifierKeys.Alt)
        {
            if (ActiveWebView?.CanGoForward == true) ActiveWebView.GoForward();
            e.Handled = true;
        }

        // Ctrl+L to focus address bar
        if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control)
        {
            FocusAddressBar();
            e.Handled = true;
        }
    }

    #endregion
}
