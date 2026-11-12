using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;
using Trowser.Robustness;

namespace Trowser.ResourceUsage;

/// <summary>
/// Runs a resource leak probe: baseline snapshot, repeated actions/reloads, GC, compare metrics.
/// </summary>
public sealed class ResourceProbe
{
    private readonly AutomationContext _ctx;
    private readonly WebView2 _webView;
    private readonly BrowserTab _tab;
    private readonly ResourceSnapshotCollector _collector;

    public ResourceProbe(AutomationContext ctx)
    {
        _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        _webView = ctx.ActiveTab.WebView;
        _tab = ctx.ActiveTab;
        _collector = new ResourceSnapshotCollector(_webView, _tab, _ctx);
    }

    public async Task<ResourceProbeResult> RunAsync(ResourceProbeOptions? options = null)
    {
        options ??= new ResourceProbeOptions();
        var iterations = Math.Clamp(options.Iterations, 1, 50);
        var startUrl = await _ctx.GetCurrentUrl();

        if (options.Actions is not { Count: > 0 } && !options.ReloadBetweenIterations)
        {
            throw new ArgumentException(
                "Resource probe requires either \"actions\" (interaction replay) or \"reloadBetweenIterations\": true.");
        }

        await _collector.PrepareForLeakDetectionAsync();
        var samples = new List<ResourceSnapshot> { await _collector.CollectAsync(prepareForLeakDetection: false) };

        for (var i = 0; i < iterations; i++)
        {
            if (options.ReloadBetweenIterations)
            {
                await _ctx.Navigate(startUrl);
                await _ctx.WaitForIdle(Math.Min(options.SettleMs, 500), 15000);
            }

            if (options.Actions is { Count: > 0 })
                await ReplayActionsAsync(options.Actions);

            if (options.SettleMs > 0)
                await Task.Delay(options.SettleMs);

            if (options.GcBetweenIterations)
                await _collector.CollectGarbageAsync();

            samples.Add(await _collector.CollectAsync(prepareForLeakDetection: false));
        }

        var findings = ResourceProbeAnalyzer.Analyze(samples, options);

        return new ResourceProbeResult
        {
            Url = startUrl,
            Timestamp = DateTime.UtcNow,
            Baseline = samples[0],
            Final = samples[^1],
            Samples = samples,
            Findings = findings
        };
    }

    public async Task<ResourceSnapshot> SnapshotAsync() =>
        await _collector.CollectAsync(prepareForLeakDetection: false);

    /// <summary>
    /// Compare a previously captured baseline to the current page (after GC). Use when the
    /// caller performs actions outside the probe — the common quicktest/script pattern.
    /// </summary>
    public async Task<ResourceProbeResult> CompareAsync(
        ResourceSnapshot baseline,
        ResourceProbeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        options ??= new ResourceProbeOptions();

        if (options.SettleMs > 0)
            await Task.Delay(options.SettleMs);

        if (options.GcBeforeFinal)
            await _collector.CollectGarbageAsync();

        var final = await _collector.CollectAsync(prepareForLeakDetection: false);
        var samples = new List<ResourceSnapshot> { baseline, final };
        var findings = ResourceProbeAnalyzer.Analyze(samples, options);
        var url = await _ctx.GetCurrentUrl();

        return new ResourceProbeResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            IsComparison = true,
            Baseline = baseline,
            Final = final,
            Samples = samples,
            Findings = findings
        };
    }

    private async Task ReplayActionsAsync(List<InterrupterAction> actions)
    {
        foreach (var act in actions)
        {
            var selector = ResolveActionSelector(act);
            try
            {
                switch (act.Action.ToLowerInvariant())
                {
                    case "click":
                        if (selector != null) await _ctx.Click(selector);
                        break;
                    case "type":
                        if (selector != null) await _ctx.Type(selector, act.Text ?? "");
                        break;
                    case "select":
                        if (selector != null) await _ctx.Select(selector, act.Value ?? "");
                        break;
                    case "hover":
                        if (selector != null) await _ctx.Hover(selector);
                        break;
                    case "press_key" or "presskey" or "key":
                        await _ctx.PressKey(act.Key ?? act.Text ?? "Enter", selector);
                        break;
                    case "scroll":
                        await _ctx.Scroll(selector, act.Value ?? "down", scrollIntoView: selector != null);
                        break;
                    case "navigate":
                        var navUrl = act.Text ?? act.Value;
                        if (!string.IsNullOrWhiteSpace(navUrl))
                            await _ctx.Navigate(navUrl);
                        break;
                    case "back" or "go_back" or "goback":
                        await GoBackAsync();
                        break;
                    case "wait" or "sleep":
                        await Task.Delay(act.DelayMs > 0 ? act.DelayMs : 1000);
                        break;
                }
            }
            catch
            {
                // Continue probe even if one action fails
            }
        }
    }

    private async Task GoBackAsync()
    {
        await _webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = _webView.CoreWebView2;
            if (core?.CanGoBack == true)
                core.GoBack();
            await Task.CompletedTask;
        });
        await _ctx.WaitForIdle(300, 10000);
    }

    private string? ResolveActionSelector(InterrupterAction act)
    {
        if (act.Ref.HasValue)
        {
            var sel = _ctx.GetSelectorByRef(act.Ref.Value);
            if (sel != null) return sel;
        }
        if (!string.IsNullOrEmpty(act.Selector)) return act.Selector;
        if (!string.IsNullOrEmpty(act.ByText)) return $"@text:{act.ByText}";
        if (!string.IsNullOrEmpty(act.Placeholder)) return $"@placeholder:{act.Placeholder}";
        if (!string.IsNullOrEmpty(act.Role))
            return $"@role:{act.Role}:{act.Name ?? ""}";
        if (!string.IsNullOrEmpty(act.Label)) return $"@label:{act.Label}";
        if (!string.IsNullOrEmpty(act.TestId)) return $"@testid:{act.TestId}";
        return null;
    }

    public static bool RequiresActiveSafetyMode(ResourceProbeOptions options)
    {
        if (options.Actions == null) return false;
        foreach (var act in options.Actions)
        {
            var a = act.Action.ToLowerInvariant();
            if (a is "click" or "type" or "select" or "hover" or "press_key" or "presskey" or "key")
                return true;
        }
        return false;
    }
}
