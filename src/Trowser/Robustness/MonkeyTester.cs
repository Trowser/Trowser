using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Robustness;

/// <summary>
/// Injects gremlins.js into the current page and runs monkey testing
/// to check application robustness under random user interactions.
///
/// Navigation is blocked during the test at two levels:
/// 1. JS-side: intercepts link clicks, form submissions, and window.open
/// 2. C#-side: WebView2 NavigationStarting handler as a safety net
/// Both record attempted navigations as findings in the result.
/// </summary>
public class MonkeyTester
{
    private readonly WebView2 _webView;
    private static string? _gremlinsScript;

    public MonkeyTester(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run a monkey test with the given options.
    /// </summary>
    public async Task<MonkeyTestResult> RunAsync(
        MonkeyTestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        options ??= new MonkeyTestOptions();
        var gremlinsScript = await GetGremlinsScriptAsync();
        var callbackId = $"__trowser_gremlins_{Guid.NewGuid():N}";

        // Track navigations blocked by the C# safety net
        var blockedNavigations = new List<string>();
        var testRunning = true;

        void OnNavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
        {
            if (!testRunning) return;
            var uri = e.Uri;
            e.Cancel = true;
            blockedNavigations.Add(uri);
        }

        // Hook navigation blocking on the UI thread
        await _webView.Dispatcher.InvokeAsync(() =>
            _webView.CoreWebView2.NavigationStarting += OnNavigationStarting);

        try
        {
            // Inject gremlins.js
            var injectResult = await WebViewUiScript.RunAsync(_webView,
                gremlinsScript + "\n; typeof gremlins !== 'undefined' ? 'OK' : 'FAIL'", cancellationToken,
                operationLabel: "Monkey test");

            if (injectResult != "OK")
            {
                throw new InvalidOperationException(
                    $"Failed to inject gremlins.js into the page. Result: {injectResult}");
            }

            // Build and start the test (includes JS-side navigation blocking)
            var testScript = BuildTestScript(callbackId, options);
            var startResult = await WebViewUiScript.RunAsync(_webView, testScript, cancellationToken,
                operationLabel: "Monkey test");

            if (startResult != "STARTED")
            {
                throw new InvalidOperationException(
                    $"Failed to start monkey test. Result: {startResult}");
            }

            // Poll for completion
            var timeoutSeconds = Math.Max(30, (int)(options.EstimatedDuration * 3) + 10);
            var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
            string? json = null;

            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string doneCheck;
                try
                {
                    doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                        cancellationToken, operationLabel: "Monkey test");
                }
                catch
                {
                    await Task.Delay(500, cancellationToken);
                    continue;
                }

                if (doneCheck == "true")
                {
                    json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                        cancellationToken, operationLabel: "Monkey test");
                    await WebViewUiScript.RunAsync(_webView,
                        $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                        cancellationToken, operationLabel: "Monkey test");
                    break;
                }
                await Task.Delay(200, cancellationToken);
            }

            if (string.IsNullOrEmpty(json))
            {
                throw new TimeoutException(
                    $"Monkey test did not complete within {timeoutSeconds} seconds.");
            }

            return ParseResults(json, options, blockedNavigations);
        }
        finally
        {
            testRunning = false;

            // Always unhook the navigation handler
            await _webView.Dispatcher.InvokeAsync(() =>
                _webView.CoreWebView2.NavigationStarting -= OnNavigationStarting);
        }
    }

    #region Script Building

    private static string BuildTestScript(string callbackId, MonkeyTestOptions options)
    {
        var seed = options.Seed ?? Random.Shared.Next(1, 999999);
        var speciesJs = BuildSpeciesArray(options.Species);

        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    var startUrl = location.href;
    var startTime = Date.now();
    var testErrors = [];
    var navAttempts = [];
    var actionCount = 0;
    var fpsReadings = [];
    var stoppedEarly = false;
    var seed = {seed};

    // === Navigation blocking (JS-side, first line of defense) ===

    // Block link clicks
    document.addEventListener('click', function(e) {{
        var link = e.target && e.target.closest ? e.target.closest('a[href]') : null;
        if (link) {{
            var href = link.getAttribute('href') || '';
            // Allow fragment-only links and javascript: hrefs
            if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {{
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                navAttempts.push({{ type: 'link', url: link.href || href }});
            }}
        }}
    }}, true);

    // Block form submissions
    document.addEventListener('submit', function(e) {{
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        navAttempts.push({{ type: 'form', url: (e.target && e.target.action) || '' }});
    }}, true);

    // Block window.open
    var origOpen = window.open;
    window.open = function(url) {{
        navAttempts.push({{ type: 'window.open', url: String(url || '') }});
        return null;
    }};

    // Block location assignments via a proxy where supported
    // (This is a best-effort approach; the C# NavigationStarting handler is the real safety net)
    try {{
        var origAssign = window.location.assign.bind(window.location);
        window.location.assign = function(url) {{
            navAttempts.push({{ type: 'location', url: String(url || '') }});
        }};
    }} catch(ex) {{}}
    try {{
        var origReplace = window.location.replace.bind(window.location);
        window.location.replace = function(url) {{
            navAttempts.push({{ type: 'location', url: String(url || '') }});
        }};
    }} catch(ex) {{}}

    // === Error interception ===

    var prevOnerror = window.onerror;
    window.onerror = function(msg, src, line, col, err) {{
        testErrors.push({{ type: 'error', message: String(msg), source: src || null, line: line || null }});
        if (prevOnerror) return prevOnerror.apply(this, arguments);
    }};

    var prevUnhandled = window.onunhandledrejection;
    window.onunhandledrejection = function(e) {{
        testErrors.push({{ type: 'unhandledrejection', message: e && e.reason ? String(e.reason) : 'Unknown promise rejection' }});
        if (prevUnhandled) prevUnhandled.apply(this, arguments);
    }};

    // === Gremlin logger ===

    var customLogger = {{
        log: function(msg) {{ actionCount++; }},
        info: function(msg) {{ actionCount++; }},
        warn: function(msg) {{
            var fpsMatch = String(msg).match(/fps\s+([\d.]+)/i);
            if (fpsMatch) fpsReadings.push(parseFloat(fpsMatch[1]));
        }},
        error: function(msg) {{
            var fpsMatch = String(msg).match(/fps\s+([\d.]+)/i);
            if (fpsMatch) {{
                fpsReadings.push(parseFloat(fpsMatch[1]));
            }} else {{
                testErrors.push({{ type: 'gremlin', message: String(msg) }});
            }}
        }}
    }};

    // === Cleanup and result compilation ===

    function finish() {{
        window.onerror = prevOnerror;
        window.onunhandledrejection = prevUnhandled;
        try {{ window.open = origOpen; }} catch(ex) {{}}

        var elapsed = (Date.now() - startTime) / 1000;
        var lowFps = fpsReadings.filter(function(f) {{ return f < 10; }});
        var lowestFps = fpsReadings.length > 0 ? Math.min.apply(null, fpsReadings) : null;

        window['{callbackId}'] = JSON.stringify({{
            startUrl: startUrl,
            endUrl: location.href,
            navigated: startUrl !== location.href,
            durationSeconds: elapsed,
            actionsPerformed: actionCount,
            seed: seed,
            errors: testErrors,
            navAttempts: navAttempts,
            fpsDrops: lowFps.length,
            lowestFps: lowestFps,
            stoppedEarly: stoppedEarly
        }});
        window['{callbackId}_done'] = true;
    }}

    // === Launch the horde ===

    try {{
        var horde = gremlins.createHorde({{
            species: {speciesJs},
            mogwais: [
                gremlins.mogwais.alert(),
                gremlins.mogwais.fps(),
                gremlins.mogwais.gizmo({{ maxErrors: {options.MaxErrors} }})
            ],
            strategies: [gremlins.strategies.distribution({{
                nb: {options.Actions},
                delay: {options.Delay}
            }})],
            logger: customLogger,
            randomizer: new gremlins.Chance(seed)
        }});

        horde.unleash().then(function() {{
            finish();
        }}).catch(function(err) {{
            if (String(err).indexOf('stopped') !== -1 || String(err).indexOf('gizmo') !== -1) {{
                stoppedEarly = true;
            }} else {{
                testErrors.push({{ type: 'horde', message: String(err) }});
            }}
            finish();
        }});
    }} catch(e) {{
        testErrors.push({{ type: 'setup', message: String(e) }});
        finish();
    }}

    return 'STARTED';
}})()";
    }

    private static string BuildSpeciesArray(MonkeySpecies species)
    {
        if (species == MonkeySpecies.All || species == MonkeySpecies.None)
            return "gremlins.allSpecies";

        var parts = new List<string>();
        if (species.HasFlag(MonkeySpecies.Clicker)) parts.Add("gremlins.species.clicker()");
        if (species.HasFlag(MonkeySpecies.Toucher)) parts.Add("gremlins.species.toucher()");
        if (species.HasFlag(MonkeySpecies.FormFiller)) parts.Add("gremlins.species.formFiller()");
        if (species.HasFlag(MonkeySpecies.Scroller)) parts.Add("gremlins.species.scroller()");
        if (species.HasFlag(MonkeySpecies.Typer)) parts.Add("gremlins.species.typer()");

        return $"[{string.Join(", ", parts)}]";
    }

    #endregion

    #region Result Parsing

    private static MonkeyTestResult ParseResults(string json, MonkeyTestOptions options,
        List<string> csharpBlockedNavigations)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var errors = new List<MonkeyTestError>();
        if (root.TryGetProperty("errors", out var errArray))
        {
            foreach (var e in errArray.EnumerateArray())
            {
                errors.Add(new MonkeyTestError
                {
                    Type = e.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                    Message = e.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "",
                    Source = e.TryGetProperty("source", out var s) && s.ValueKind != JsonValueKind.Null
                        ? s.GetString() : null,
                    Line = e.TryGetProperty("line", out var l) && l.ValueKind == JsonValueKind.Number
                        ? l.GetInt32() : null
                });
            }
        }

        // Merge JS-side and C#-side navigation attempts
        var navAttempts = new List<NavigationAttempt>();
        if (root.TryGetProperty("navAttempts", out var navArray))
        {
            foreach (var n in navArray.EnumerateArray())
            {
                navAttempts.Add(new NavigationAttempt
                {
                    Type = n.TryGetProperty("type", out var nt) ? nt.GetString() ?? "" : "",
                    Url = n.TryGetProperty("url", out var nu) ? nu.GetString() ?? "" : ""
                });
            }
        }
        foreach (var url in csharpBlockedNavigations)
        {
            navAttempts.Add(new NavigationAttempt { Type = "navigation", Url = url });
        }

        return new MonkeyTestResult
        {
            StartUrl = root.TryGetProperty("startUrl", out var su) ? su.GetString() ?? "" : "",
            EndUrl = root.TryGetProperty("endUrl", out var eu) ? eu.GetString() ?? "" : "",
            Navigated = root.TryGetProperty("navigated", out var nav) && nav.GetBoolean(),
            Timestamp = DateTime.UtcNow,
            DurationSeconds = root.TryGetProperty("durationSeconds", out var d) ? d.GetDouble() : 0,
            ActionsPerformed = root.TryGetProperty("actionsPerformed", out var a) ? a.GetInt32() : 0,
            Seed = root.TryGetProperty("seed", out var se) ? se.GetInt32() : 0,
            Options = options,
            Errors = errors,
            NavigationAttempts = navAttempts,
            FpsDrops = root.TryGetProperty("fpsDrops", out var fd) ? fd.GetInt32() : 0,
            LowestFps = root.TryGetProperty("lowestFps", out var lf) && lf.ValueKind == JsonValueKind.Number
                ? lf.GetDouble() : null,
            StoppedEarly = root.TryGetProperty("stoppedEarly", out var st) && st.GetBoolean()
        };
    }

    #endregion

    #region Resource Loading

    private static async Task<string> GetGremlinsScriptAsync()
    {
        if (_gremlinsScript != null) return _gremlinsScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.gremlins.min.js")
            ?? throw new FileNotFoundException("gremlins.js not found as embedded resource.");

        using var reader = new StreamReader(stream);
        _gremlinsScript = await reader.ReadToEndAsync();
        return _gremlinsScript;
    }

    #endregion

}
