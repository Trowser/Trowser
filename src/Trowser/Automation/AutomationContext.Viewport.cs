using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Viewport

    private (int Width, int Height)? _viewportOverride;

    /// <summary>
    /// Well-known viewport presets for responsive design testing.
    /// Desktop maps to (0,0) meaning "reset to full screen."
    /// </summary>
    public static readonly Dictionary<string, (int Width, int Height)> ViewportPresets = new()
    {
        ["SmallPhone"] = (320, 568),
        ["BigPhone"] = (412, 915),
        ["LandscapePhone"] = (844, 390),
        ["SmallPad"] = (768, 1024),
        ["BigPad"] = (1024, 1366),
        ["Desktop"] = (0, 0),
        ["BigDesktop"] = (1920, 1080)
    };

    /// <summary>
    /// The currently active viewport override, or null if using the default (full screen).
    /// </summary>
    public (int Width, int Height)? ViewportOverride => _viewportOverride;

    /// <summary>
    /// Set the browser viewport to exact pixel dimensions using Chrome DevTools Protocol.
    /// The Trowser window stays the same size — only the page rendering viewport changes.
    /// Media queries, window.innerWidth/innerHeight, and layout all respond to the new size.
    /// </summary>
    public async Task SetViewport(int width, int height)
    {
        if (width < 200 || width > 7680)
            throw new ArgumentOutOfRangeException(nameof(width), "Viewport width must be between 200 and 7680 pixels.");
        if (height < 200 || height > 4320)
            throw new ArgumentOutOfRangeException(nameof(height), "Viewport height must be between 200 and 4320 pixels.");

        var json = $"{{\"width\":{width},\"height\":{height},\"deviceScaleFactor\":0,\"mobile\":false}}";

        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Emulation.setDeviceMetricsOverride", json);
            webView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 30, 30, 30);
        });

        _viewportOverride = (width, height);
    }

    /// <summary>
    /// Set the viewport to a named preset: SmallPhone, BigPhone, LandscapePhone, SmallPad, BigPad, Desktop, BigDesktop.
    /// Desktop resets to full screen (clears the override).
    /// </summary>
    public async Task SetViewport(string preset)
    {
        var normalized = preset.ToLowerInvariant().Replace(" ", "").Replace("-", "").Replace("_", "");
        var match = ViewportPresets.FirstOrDefault(p =>
            p.Key.Equals(normalized, StringComparison.OrdinalIgnoreCase));

        if (match.Key == null)
        {
            var valid = string.Join(", ", ViewportPresets.Keys);
            throw new ArgumentException($"Unknown viewport preset: '{preset}'. Valid presets: {valid}");
        }

        if (match.Value.Width == 0)
        {
            await ResetViewport();
            return;
        }

        await SetViewport(match.Value.Width, match.Value.Height);
    }

    /// <summary>
    /// Reset the viewport to full screen (clear the device metrics override).
    /// Equivalent to SetViewport("Desktop").
    /// </summary>
    public async Task ResetViewport()
    {
        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Emulation.clearDeviceMetricsOverride", "{}");
            webView.DefaultBackgroundColor = System.Drawing.Color.White;
        });

        _viewportOverride = null;
    }

    /// <summary>
    /// Get the current effective viewport size (as seen by the page).
    /// </summary>
    public async Task<(int Width, int Height)> GetViewportSize()
    {
        var js = "(function(){return JSON.stringify({w:window.innerWidth,h:window.innerHeight});})()";
        var result = await RunJs(js);
        return ParseViewportSizeJson(result);
    }

    /// <summary>Layout viewport of a frame document (for frame-scoped snapshots and audits).</summary>
    public async Task<(int Width, int Height)> GetViewportSizeInFrame(string frame)
    {
        var js = "(function(){return JSON.stringify({w:window.innerWidth,h:window.innerHeight});})()";
        var result = await ExecuteJsInFrame(frame, js);
        return ParseViewportSizeJson(result);
    }

    private static (int Width, int Height) ParseViewportSizeJson(string result)
    {
        try
        {
            using var doc = JsonDocument.Parse(result);
            var w = doc.RootElement.GetProperty("w").GetInt32();
            var h = doc.RootElement.GetProperty("h").GetInt32();
            return (w, h);
        }
        catch
        {
            return (0, 0);
        }
    }

    #endregion

    #region Screen Curtain

    private bool _screenCurtainEnabled;

    /// <summary>Whether the visual screen curtain overlay is active (page hidden from sight, not from screen readers).</summary>
    public bool ScreenCurtainEnabled => _screenCurtainEnabled;

    /// <summary>In-page black overlay for blind testing mode.</summary>
    public ScreenCurtainManager ScreenCurtain { get; } = new();

    /// <summary>Toggle the screen curtain. Returns the new enabled state.</summary>
    public async Task<bool> ToggleScreenCurtain()
        => await SetScreenCurtain(!_screenCurtainEnabled);

    /// <summary>Enable or disable the screen curtain overlay.</summary>
    public async Task<bool> SetScreenCurtain(bool enabled)
    {
        if (_screenCurtainEnabled == enabled)
            return _screenCurtainEnabled;

        _screenCurtainEnabled = enabled;
        await SyncScreenCurtainToAllTabsAsync();
        Log(enabled ? "Screen curtain ON" : "Screen curtain OFF");
        return _screenCurtainEnabled;
    }

    /// <summary>Apply or remove the screen curtain on every open tab.</summary>
    public async Task SyncScreenCurtainToAllTabsAsync()
    {
        if (_tabs.Count == 0) return;
        var anchor = _tabs.FirstOrDefault(t => t.WebView != null)?.WebView;
        if (anchor == null) return;

        await await anchor.Dispatcher.InvokeAsync(async () =>
        {
            foreach (var tab in _tabs)
            {
                var wv = tab.WebView;
                if (wv?.CoreWebView2 == null) continue;
                if (_screenCurtainEnabled)
                    await ScreenCurtain.ApplyAsync(wv);
                else
                    await ScreenCurtain.RemoveAsync(wv);
            }
        });
    }

    #endregion
}
