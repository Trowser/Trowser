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
    #region Navigation

    private const int NavigationTimeoutMs = 30_000;

    /// <summary>
    /// True when <paramref name="targetUrl"/> points at the same document as <paramref name="currentSource"/>
    /// (scheme, host, path, query) but a different fragment. WebView2 often omits
    /// <see cref="CoreWebView2.NavigationCompleted"/> for that case. We wait on
    /// <see cref="CoreWebView2.SourceChanged"/>, <see cref="CoreWebView2.HistoryChanged"/>, and a URL-filtered
    /// <see cref="CoreWebView2.NavigationCompleted"/> (same pattern as <see cref="NavigateHistoryByDelta"/> for SPA history).
    /// </summary>
    private static bool IsHashOnlyDocumentNavigation(string? currentSource, string targetUrl)
    {
        if (string.IsNullOrEmpty(currentSource) || string.IsNullOrEmpty(targetUrl))
            return false;
        if (!Uri.TryCreate(currentSource, UriKind.Absolute, out var cur))
            return false;
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var tgt))
            return false;

        if (Uri.Compare(cur, tgt,
                UriComponents.SchemeAndServer | UriComponents.Path | UriComponents.Query,
                UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) != 0)
            return false;

        return !string.Equals(cur.Fragment, tgt.Fragment, StringComparison.Ordinal);
    }

    /// <summary>Whether a navigate request targets the same document as the current address (API reload semantics).</summary>
    public static bool UrlEquivalentForNavigate(string? currentSource, string targetUrl) =>
        UrlMatchesNavigateTarget(currentSource, targetUrl);

    /// <summary>
    /// Stable URL string for API responses (<c>/api/navigate</c>, <c>/api/state</c>) — percent-encodes query and fragment
    /// consistently (avoids mixed decoded/encoded segments from <see cref="Uri.ToString"/>).
    /// </summary>
    public static string FormatUrlForApi(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
            return raw.Trim();

        return uri.GetComponents(
            UriComponents.SchemeAndServer | UriComponents.Path | UriComponents.Query | UriComponents.Fragment,
            UriFormat.UriEscaped);
    }

    /// <summary>
    /// Resolve a fetch URL against the active document when relative. Returns null when the URL cannot be resolved.
    /// </summary>
    public async Task<string?> ResolveFetchUrlAsync(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        var trimmed = url.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute)
            && (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps))
            return FormatUrlForApi(trimmed);

        var pageUrl = await GetCurrentUrl();
        if (string.IsNullOrEmpty(pageUrl))
            return null;
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri))
            return null;
        if (!Uri.TryCreate(baseUri, trimmed, out var resolved)
            || (resolved.Scheme != Uri.UriSchemeHttp && resolved.Scheme != Uri.UriSchemeHttps))
            return null;

        return FormatUrlForApi(resolved.ToString());
    }

    /// <summary>Whether <paramref name="currentSource"/> is already the navigated address (after normalization).</summary>
    private static bool UrlMatchesNavigateTarget(string? currentSource, string targetUrl)
    {
        if (string.IsNullOrEmpty(currentSource) || string.IsNullOrEmpty(targetUrl))
            return false;
        if (!Uri.TryCreate(currentSource, UriKind.Absolute, out var cur))
            return false;
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var tgt))
            return false;

        return Uri.Compare(cur, tgt,
            UriComponents.SchemeAndServer | UriComponents.Path | UriComponents.Query | UriComponents.Fragment,
            UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;
    }

    private static bool SameOrigin(Uri a, Uri b) =>
        Uri.Compare(a, b, UriComponents.SchemeAndServer, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;

    /// <summary>
    /// True when the tab moved to a new same-origin URL after a link click even though the resolved
    /// <c>href</c> never matched (common SPA pattern: placeholder root URL + <c>pushState</c> to a detail route).
    /// </summary>
    public static bool SpNavigationSucceededDespiteStaleHref(string? urlAtStart, string? currentUrl, string expectedHref)
    {
        if (string.IsNullOrEmpty(urlAtStart) || string.IsNullOrEmpty(currentUrl))
            return false;
        if (UrlMatchesNavigateTarget(urlAtStart, currentUrl))
            return false;
        if (!Uri.TryCreate(urlAtStart, UriKind.Absolute, out var startUri))
            return false;
        if (!Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            return false;
        if (!Uri.TryCreate(expectedHref, UriKind.Absolute, out var hrefUri))
            return false;

        return SameOrigin(startUri, currentUri) && SameOrigin(hrefUri, currentUri);
    }

    /// <summary>Whether a post-click navigation wait can end (exact href match or accepted SPA route change).</summary>
    public static bool NavWaitSatisfied(string? urlAtStart, string? currentUrl, string targetUrl) =>
        UrlMatchesNavigateTarget(currentUrl, targetUrl)
        || SpNavigationSucceededDespiteStaleHref(urlAtStart, currentUrl, targetUrl);

    /// <summary>
    /// Wait until the active tab reaches <paramref name="targetUrl"/> after a click or in-page navigation.
    /// Uses hash/History signals for same-document route changes (SPA, hash routers).
    /// </summary>
    internal async Task WaitForTargetUrlAsync(string targetUrl, int timeoutMs = 5000)
    {
        var webView = ActiveTab.WebView;
        var urlAtStart = await webView.Dispatcher.InvokeAsync(() =>
            webView.Source is { } u ? u.ToString() : null);
        if (NavWaitSatisfied(urlAtStart, urlAtStart, targetUrl))
            return;

        var waitHashOnly = IsHashOnlyDocumentNavigation(urlAtStart, targetUrl);
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void UnsubscribeAll()
        {
            webView.CoreWebView2.SourceChanged -= OnLocationMaybeDone;
            webView.CoreWebView2.HistoryChanged -= OnLocationMaybeDone;
            webView.CoreWebView2.NavigationCompleted -= OnNavigationCompleted;
        }

        void TryComplete(string? src)
        {
            if (!NavWaitSatisfied(urlAtStart, src, targetUrl))
                return;
            UnsubscribeAll();
            tcs.TrySetResult(true);
        }

        void OnLocationMaybeDone(object? s, object? e)
        {
            var src = webView.Source is { } u ? u.ToString() : null;
            TryComplete(src);
        }

        void OnNavigationCompleted(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            if (waitHashOnly)
            {
                var src = webView.Source is { } u ? u.ToString() : null;
                TryComplete(src);
                return;
            }

            UnsubscribeAll();
            tcs.TrySetResult(true);
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.SourceChanged += OnLocationMaybeDone;
            webView.CoreWebView2.HistoryChanged += OnLocationMaybeDone;
            webView.CoreWebView2.NavigationCompleted += OnNavigationCompleted;
        });

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            await tcs.Task.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(UnsubscribeAll);

            if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                throw;

            var finalSource = await webView.Dispatcher.InvokeAsync(() =>
                webView.Source is { } u ? u.ToString() : null);
            if (NavWaitSatisfied(urlAtStart, finalSource, targetUrl))
                return;

            throw new TimeoutException(
                $"Timed out after {timeoutMs}ms waiting for URL {targetUrl} (hash/SPA routes use SourceChanged, not full navigation).");
        }
    }

    /// <summary>
    /// Navigate to a URL and wait for the page to finish loading.
    /// Throws if the URL is outside the configured navigation scope.
    /// Times out after 30 seconds to prevent permanent hangs.
    /// </summary>
    public Task Navigate(string url, bool reload = false, bool ignoreCertificateErrors = false) =>
        NavigateCore(url, reload, ignoreCertificateErrors);

    private async Task NavigateCore(string url, bool reload, bool ignoreCertificateErrors)
    {
        await CheckScriptExecutionAsync();

        var priorIgnore = IgnoreCertificateErrors;
        if (ignoreCertificateErrors)
            IgnoreCertificateErrors = true;

        try
        {
        url = url.Trim();
        if (!url.Contains("://") && !url.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
        {
            url = "https://" + url;
        }

        if (url.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
        {
            // about:blank and other about: URLs bypass navigation scope
        }
        else if (NavigationGuard != null && !NavigationGuard.IsAllowed(url))
        {
            throw new InvalidOperationException(
                $"Navigation blocked: {url} is outside the navigation scope ({NavigationGuard.Scope}). " +
                $"Change the scope in Trowser settings to allow this URL.");
        }

        var webView = ActiveTab.WebView;
        var currentSource = await webView.Dispatcher.InvokeAsync(() =>
            webView.Source is { } u ? u.ToString() : null);
        if (!reload && UrlMatchesNavigateTarget(currentSource, url))
        {
            try { await RecordTraceStepAsync("navigate", new { url, skipped = true }); }
            catch { /* best-effort */ }
            return;
        }

        var waitHashOnly = IsHashOnlyDocumentNavigation(currentSource, url);

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void UnsubscribeHashListeners()
        {
            webView.CoreWebView2.SourceChanged -= HashLocationSignal;
            webView.CoreWebView2.HistoryChanged -= HashLocationSignal;
            webView.CoreWebView2.NavigationCompleted -= HashNavCompleted;
        }

        void UnsubscribeFullNavigationListener()
        {
            webView.CoreWebView2.NavigationCompleted -= NavDone;
        }

        void NavDone(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            UnsubscribeFullNavigationListener();
            ActiveTab.LastNavigationSucceeded = e.IsSuccess;
            ActiveTab.LastNavigationWebErrorStatus = e.IsSuccess ? null : e.WebErrorStatus.ToString();
            tcs.TrySetResult(e.IsSuccess);
        }

        void HashLocationSignal(object? s, object? e)
        {
            var src = webView.Source is { } u ? u.ToString() : null;
            if (!UrlMatchesNavigateTarget(src, url))
                return;
            UnsubscribeHashListeners();
            tcs.TrySetResult(true);
        }

        void HashNavCompleted(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            var src = webView.Source is { } u ? u.ToString() : null;
            if (!UrlMatchesNavigateTarget(src, url))
                return;
            UnsubscribeHashListeners();
            ActiveTab.LastNavigationSucceeded = e.IsSuccess;
            ActiveTab.LastNavigationWebErrorStatus = e.IsSuccess ? null : e.WebErrorStatus.ToString();
            tcs.TrySetResult(e.IsSuccess);
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            if (waitHashOnly)
            {
                webView.CoreWebView2.SourceChanged += HashLocationSignal;
                webView.CoreWebView2.HistoryChanged += HashLocationSignal;
                webView.CoreWebView2.NavigationCompleted += HashNavCompleted;
            }
            else
                webView.CoreWebView2.NavigationCompleted += NavDone;
            webView.CoreWebView2.Navigate(url);
        });

        bool success = true;
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
        timeoutCts.CancelAfter(NavigationTimeoutMs);
        try
        {
            success = await tcs.Task.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(() =>
            {
                if (waitHashOnly)
                    UnsubscribeHashListeners();
                else
                    UnsubscribeFullNavigationListener();
            });

            if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                throw;

            var finalSource = await webView.Dispatcher.InvokeAsync(() =>
                webView.Source is { } u ? u.ToString() : null);
            if (UrlMatchesNavigateTarget(finalSource, url))
            {
                success = true;
            }
            else
            {
                throw new TimeoutException(
                    $"Navigation to {url} timed out after {NavigationTimeoutMs / 1000} seconds. " +
                    "The page may be stuck loading, the target is a client-side route (hash/SPA) that did not " +
                    "emit WebView2 navigation events, or a previous location.reload() left the browser in a bad state.");
            }
        }

        if (!success)
        {
            Log($"[Warning] Navigation to {url} completed with errors");
        }

        // Ensure geo/permissions are bound to the new origin before the next script step.
        // (NavigationCompleted also triggers this asynchronously; awaiting here avoids a race.)
        try { await ReapplyEmulationAfterNavigationAsync(); }
        catch { /* best-effort */ }

        try { await RecordTraceStepAsync("navigate", new { url }); }
        catch { /* best-effort */ }
        }
        finally
        {
            if (ignoreCertificateErrors)
                IgnoreCertificateErrors = priorIgnore;
        }
    }

    /// <summary>
    /// Issue a fresh GET navigation to <paramref name="url"/> via CDP <c>Page.navigate</c>, even when
    /// the address bar already matches. Avoids <see cref="Reload"/> re-submitting a prior form POST.
    /// </summary>
    public Task NavigateFreshGetAsync(string url, bool ignoreCertificateErrors = false) =>
        NavigateFreshGetCore(url, ignoreCertificateErrors);

    private const string DocumentNavigationSignatureJs = """
        (function(){
          var n = performance.getEntriesByType('navigation')[0];
          if (!n) return '';
          return String(n.startTime) + '|' + n.type + '|' + String(n.loadEventEnd || 0);
        })()
        """;

    private async Task<string> GetDocumentNavigationSignatureAsync()
    {
        try
        {
            return await RunJs(DocumentNavigationSignatureJs);
        }
        catch
        {
            return "";
        }
    }

    private async Task NavigateFreshGetCore(string url, bool ignoreCertificateErrors)
    {
        await CheckScriptExecutionAsync();

        var priorIgnore = IgnoreCertificateErrors;
        if (ignoreCertificateErrors)
            IgnoreCertificateErrors = true;

        try
        {
            url = url.Trim();
            if (!url.Contains("://") && !url.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
                url = "https://" + url;

            if (!url.StartsWith("about:", StringComparison.OrdinalIgnoreCase)
                && NavigationGuard != null && !NavigationGuard.IsAllowed(url))
            {
                throw new InvalidOperationException(
                    $"Navigation blocked: {url} is outside the navigation scope ({NavigationGuard.Scope}). " +
                    $"Change the scope in Trowser settings to allow this URL.");
            }

            var baselineSig = await GetDocumentNavigationSignatureAsync();
            var webView = ActiveTab.WebView;
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            void UnsubscribeFreshGetListeners()
            {
                webView.CoreWebView2.NavigationCompleted -= NavDone;
                webView.ContentLoading -= ContentLoadingSignal;
            }

            void NavDone(object? s, CoreWebView2NavigationCompletedEventArgs e)
            {
                UnsubscribeFreshGetListeners();
                ActiveTab.LastNavigationSucceeded = e.IsSuccess;
                ActiveTab.LastNavigationWebErrorStatus = e.IsSuccess ? null : e.WebErrorStatus.ToString();
                tcs.TrySetResult(e.IsSuccess);
            }

            void ContentLoadingSignal(object? s, CoreWebView2ContentLoadingEventArgs e)
            {
                if (!e.IsErrorPage)
                    tcs.TrySetResult(true);
            }

            await webView.Dispatcher.InvokeAsync(async () =>
            {
                webView.CoreWebView2.NavigationCompleted += NavDone;
                webView.ContentLoading += ContentLoadingSignal;
                try
                {
                    var navPayload = JsonSerializer.Serialize(new { url });
                    await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.navigate", navPayload)
                        .ConfigureAwait(true);
                }
                catch
                {
                    UnsubscribeFreshGetListeners();
                    throw;
                }
            });

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
            timeoutCts.CancelAfter(NavigationTimeoutMs);
            var eventCompleted = false;
            try
            {
                eventCompleted = await tcs.Task.WaitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                await webView.Dispatcher.InvokeAsync(UnsubscribeFreshGetListeners);
                if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                    throw;

                var polled = await WaitForFreshGetNavigationSignalAsync(baselineSig, TimeSpan.FromSeconds(2));
                eventCompleted = polled;
            }

            var afterSig = await GetDocumentNavigationSignatureAsync();
            var documentReloaded = !string.IsNullOrEmpty(afterSig)
                                   && !string.Equals(afterSig, baselineSig, StringComparison.Ordinal);
            ActiveTab.LastSameUrlFreshGetDocumentReloaded = documentReloaded;

            if (!eventCompleted && !documentReloaded)
            {
                ActiveTab.LastNavigationSucceeded = true;
                ActiveTab.LastNavigationWebErrorStatus = null;
                try { await RecordTraceStepAsync("navigate", new { url, freshGet = true, documentReloaded = false, noOp = true }); }
                catch { /* best-effort */ }
                return;
            }

            if (!eventCompleted && documentReloaded)
            {
                ActiveTab.LastNavigationSucceeded = true;
                ActiveTab.LastNavigationWebErrorStatus = null;
            }

            try { await ReapplyEmulationAfterNavigationAsync(); }
            catch { /* best-effort */ }

            try { await RecordTraceStepAsync("navigate", new { url, freshGet = true, documentReloaded }); }
            catch { /* best-effort */ }
        }
        finally
        {
            if (ignoreCertificateErrors)
                IgnoreCertificateErrors = priorIgnore;
        }
    }

    private async Task<bool> WaitForFreshGetNavigationSignalAsync(string baselineSig, TimeSpan extraWait)
    {
        var deadline = DateTime.UtcNow.Add(extraWait);
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(100, ScriptCancellation);
            var sig = await GetDocumentNavigationSignatureAsync();
            if (!string.IsNullOrEmpty(sig) && !string.Equals(sig, baselineSig, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// True when the most recent document request to the same URL used POST (form navigation).
    /// </summary>
    public static bool LastDocumentRequestWasPost(IReadOnlyList<NetworkEntry> entries, string? currentUrl)
    {
        if (string.IsNullOrEmpty(currentUrl))
            return false;

        for (var i = entries.Count - 1; i >= 0; i--)
        {
            var e = entries[i];
            if (!string.Equals(e.Method, "POST", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!UrlEquivalentForNavigate(e.Url, currentUrl))
                continue;
            if (string.Equals(e.ResourceType, "Document", StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrEmpty(e.RequestBody))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Reload the current page (like the browser refresh button) and wait for it to finish loading.
    /// Unlike <see cref="Navigate"/> with the current URL — which is a no-op when the address already
    /// matches — this always re-fetches the document, so in-progress form input, DOM state, and
    /// client-side caches are discarded. Times out after 30 seconds.
    /// </summary>
    public async Task Reload()
    {
        await CheckScriptExecutionAsync();

        var webView = ActiveTab.WebView;
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void NavDone(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            webView.CoreWebView2.NavigationCompleted -= NavDone;
            tcs.TrySetResult(e.IsSuccess);
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.NavigationCompleted += NavDone;
            webView.CoreWebView2.Reload();
        });

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
        timeoutCts.CancelAfter(NavigationTimeoutMs);
        try
        {
            var success = await tcs.Task.WaitAsync(timeoutCts.Token);
            if (!success)
                Log("[Warning] Reload completed with errors");
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(() => webView.CoreWebView2.NavigationCompleted -= NavDone);
            if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                throw;
            throw new TimeoutException(
                $"Reload timed out after {NavigationTimeoutMs / 1000} seconds. The page may be stuck loading.");
        }
    }

    /// <summary>Best-effort CDP script termination when <c>POST /api/abort</c> cancels a stuck operation.</summary>
    public void TryTerminatePageScriptsForAbort()
    {
        try
        {
            WebViewCdpRecovery.TryTerminateExecutionAsync(ActiveTab.WebView);
        }
        catch
        {
            // ignore
        }
    }

    /// <summary>
    /// Recover from a hung page (infinite loop, DoS script, heavy synchronous JS) by calling CDP
    /// <c>Runtime.terminateExecution</c> (optional) and <c>Page.navigate</c>, which do not depend on the
    /// page&apos;s JavaScript event loop. Used by <c>POST /api/force-navigate</c> (bypasses the API gate).
    /// </summary>
    /// <param name="url">Target URL (e.g. <c>about:blank</c>).</param>
    /// <param name="terminateScripts">When true, runs <c>Runtime.terminateExecution</c> before navigation.</param>
    public async Task ForceNavigateAsync(string url, bool terminateScripts = true)
    {
        url = url.Trim();
        if (!url.Contains("://") && !url.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            url = "https://" + url;

        if (url.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
        {
            // about:blank and other about: URLs bypass navigation scope
        }
        else if (NavigationGuard != null && !NavigationGuard.IsAllowed(url))
        {
            throw new InvalidOperationException(
                $"Navigation blocked: {url} is outside the navigation scope ({NavigationGuard.Scope}). " +
                "Change the scope in Trowser settings to allow this URL.");
        }

        var webView = ActiveTab.WebView;
        var currentSource = await webView.Dispatcher.InvokeAsync(() =>
            webView.Source is { } u ? u.ToString() : null);
        if (UrlMatchesNavigateTarget(currentSource, url))
            return;

        var waitHashOnly = IsHashOnlyDocumentNavigation(currentSource, url);

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void UnsubscribeHashListeners()
        {
            webView.CoreWebView2.SourceChanged -= HashLocationSignal;
            webView.CoreWebView2.HistoryChanged -= HashLocationSignal;
            webView.CoreWebView2.NavigationCompleted -= HashNavCompleted;
        }

        void UnsubscribeFullNavigationListener()
        {
            webView.CoreWebView2.NavigationCompleted -= NavDone;
        }

        void NavDone(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            UnsubscribeFullNavigationListener();
            tcs.TrySetResult(e.IsSuccess);
        }

        void HashLocationSignal(object? s, object? e)
        {
            var src = webView.Source is { } u ? u.ToString() : null;
            if (!UrlMatchesNavigateTarget(src, url))
                return;
            UnsubscribeHashListeners();
            tcs.TrySetResult(true);
        }

        void HashNavCompleted(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            var src = webView.Source is { } u ? u.ToString() : null;
            if (!UrlMatchesNavigateTarget(src, url))
                return;
            UnsubscribeHashListeners();
            tcs.TrySetResult(e.IsSuccess);
        }

        await webView.Dispatcher.InvokeAsync(async () =>
        {
            if (waitHashOnly)
            {
                webView.CoreWebView2.SourceChanged += HashLocationSignal;
                webView.CoreWebView2.HistoryChanged += HashLocationSignal;
                webView.CoreWebView2.NavigationCompleted += HashNavCompleted;
            }
            else
                webView.CoreWebView2.NavigationCompleted += NavDone;

            try
            {
                if (terminateScripts)
                {
                    try
                    {
                        await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Runtime.terminateExecution", "{}")
                            .ConfigureAwait(true);
                    }
                    catch (Exception ex)
                    {
                        Log($"[ForceNavigate] Runtime.terminateExecution: {ex.Message}");
                    }
                }

                var navPayload = JsonSerializer.Serialize(new { url });
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.navigate", navPayload)
                    .ConfigureAwait(true);
            }
            catch
            {
                if (waitHashOnly)
                    UnsubscribeHashListeners();
                else
                    UnsubscribeFullNavigationListener();
                throw;
            }
        });

        bool success = true;
        using var timeoutCts = new CancellationTokenSource();
        timeoutCts.CancelAfter(NavigationTimeoutMs);
        try
        {
            success = await tcs.Task.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(() =>
            {
                if (waitHashOnly)
                    UnsubscribeHashListeners();
                else
                    UnsubscribeFullNavigationListener();
            });

            var finalSource = await webView.Dispatcher.InvokeAsync(() =>
                webView.Source is { } u ? u.ToString() : null);
            if (UrlMatchesNavigateTarget(finalSource, url))
            {
                success = true;
            }
            else
            {
                throw new TimeoutException(
                    $"Force navigation to {url} timed out after {NavigationTimeoutMs / 1000} seconds.");
            }
        }

        if (!success)
            Log($"[Warning] Force navigation to {url} completed with errors");
    }

    /// <summary>
    /// Navigate back in session history using CDP <c>Page.getNavigationHistory</c> + <c>Page.navigateToHistoryEntry</c>.
    /// Waits for <see cref="CoreWebView2.NavigationCompleted"/> or <see cref="CoreWebView2.HistoryChanged"/> so
    /// same-document history moves (SPA, <c>pushState</c>) do not hang — unlike <c>CoreWebView2.GoBack()</c> alone.
    /// </summary>
    public Task GoBack() => NavigateHistoryByDelta(-1);

    /// <summary>
    /// Navigate forward in session history (see <see cref="GoBack"/>).
    /// </summary>
    public Task GoForward() => NavigateHistoryByDelta(1);

    /// <summary>
    /// Move one step in session history via CDP. <paramref name="delta"/> must be <c>-1</c> (back) or <c>1</c> (forward).
    /// </summary>
    private async Task NavigateHistoryByDelta(int delta)
    {
        await CheckScriptExecutionAsync();
        if (delta is not (-1) and not 1)
            throw new ArgumentOutOfRangeException(nameof(delta), delta, "Only -1 (back) and 1 (forward) are supported.");

        var webView = ActiveTab.WebView;

        string historyJson;
        try
        {
            historyJson = await await webView.Dispatcher.InvokeAsync(async () =>
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.getNavigationHistory", "{}")
                    .ConfigureAwait(true));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to read navigation history: {ex.Message}", ex);
        }

        long entryId;
        using (var doc = JsonDocument.Parse(historyJson))
        {
            var root = doc.RootElement;
            if (!root.TryGetProperty("currentIndex", out var curEl) ||
                !root.TryGetProperty("entries", out var entriesEl) ||
                entriesEl.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidOperationException("Unexpected Page.getNavigationHistory response.");
            }

            var currentIndex = curEl.GetInt32();
            var count = entriesEl.GetArrayLength();
            var targetIndex = currentIndex + delta;
            if (targetIndex < 0 || targetIndex >= count)
            {
                throw new InvalidOperationException(
                    delta < 0
                        ? "Cannot go back: no history to go back to."
                        : "Cannot go forward: no history to go forward to.");
            }

            var entry = entriesEl[targetIndex];
            if (!entry.TryGetProperty("id", out var idEl))
                throw new InvalidOperationException("Navigation history entry missing id.");

            entryId = idEl.ValueKind == JsonValueKind.String
                ? long.Parse(idEl.GetString()!, System.Globalization.CultureInfo.InvariantCulture)
                : idEl.GetInt64();
        }

        var navPayload = JsonSerializer.Serialize(new { entryId });

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void NavDone(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            webView.CoreWebView2.NavigationCompleted -= NavDone;
            webView.CoreWebView2.HistoryChanged -= HistDone;
            tcs.TrySetResult(e.IsSuccess);
        }

        void HistDone(object? s, object? e)
        {
            webView.CoreWebView2.NavigationCompleted -= NavDone;
            webView.CoreWebView2.HistoryChanged -= HistDone;
            tcs.TrySetResult(true);
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.NavigationCompleted += NavDone;
            webView.CoreWebView2.HistoryChanged += HistDone;
        });

        try
        {
            await await webView.Dispatcher.InvokeAsync(async () =>
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.navigateToHistoryEntry", navPayload)
                    .ConfigureAwait(true));
        }
        catch
        {
            await webView.Dispatcher.InvokeAsync(() =>
            {
                webView.CoreWebView2.NavigationCompleted -= NavDone;
                webView.CoreWebView2.HistoryChanged -= HistDone;
            });
            throw;
        }

        bool success;
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
        timeoutCts.CancelAfter(NavigationTimeoutMs);
        try
        {
            success = await tcs.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(() =>
            {
                webView.CoreWebView2.NavigationCompleted -= NavDone;
                webView.CoreWebView2.HistoryChanged -= HistDone;
            });

            if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                throw;

            throw new TimeoutException(
                delta < 0
                    ? $"GoBack timed out after {NavigationTimeoutMs / 1000} seconds."
                    : $"GoForward timed out after {NavigationTimeoutMs / 1000} seconds.");
        }

        if (!success)
        {
            Log(delta < 0 ? "[Warning] GoBack completed with errors" : "[Warning] GoForward completed with errors");
        }
    }

    #endregion

    #region Page Assertions

    public async Task AssertPageContains(string expectedText, string? message = null)
    {
        var pageText = await GetPageText();
        var truncated = expectedText.Length > 60 ? expectedText[..57] + "..." : expectedText;
        var desc = message ?? $"Page contains: \"{truncated}\"";

        if (pageText.Contains(expectedText, StringComparison.Ordinal))
            Assert.Pass(desc);
        else
            Assert.Fail(desc);
    }

    public async Task AssertPageNotContains(string unexpectedText, string? message = null)
    {
        var pageText = await GetPageText();
        var truncated = unexpectedText.Length > 60 ? unexpectedText[..57] + "..." : unexpectedText;
        var desc = message ?? $"Page does not contain: \"{truncated}\"";

        if (!pageText.Contains(unexpectedText, StringComparison.Ordinal))
            Assert.Pass(desc);
        else
            Assert.Fail(desc);
    }

    public async Task AssertElementVisible(string selector, string? message = null)
    {
        var desc = message ?? $"Element visible: {selector}";
        try
        {
            // Resolve semantic locators (@role:, @label:, etc.) to a CSS selector via WaitForActionable
            var resolved = await WaitForActionable(selector, DefaultActionTimeout, requireVisible: true, requireEnabled: false);
            var js = WrapWithDeepQuery($@"
                var el = deepQuery({JsonEscape(resolved)});
                if (!el) return 'NOT_FOUND';
                var rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return 'ZERO_SIZE';
                var style = window.getComputedStyle(el);
                if (style.display === 'none') return 'DISPLAY_NONE';
                if (style.visibility === 'hidden') return 'VISIBILITY_HIDDEN';
                if (parseFloat(style.opacity) === 0) return 'OPACITY_ZERO';
                return 'VISIBLE';
            ");
            var result = await RunJs(js);
            if (result == "VISIBLE")
                Assert.Pass(desc);
            else
                Assert.Fail(desc, result switch
                {
                    "NOT_FOUND" => $"Element not found: {selector}",
                    "ZERO_SIZE" => "Element has zero size",
                    "DISPLAY_NONE" => "Element has display: none",
                    "VISIBILITY_HIDDEN" => "Element has visibility: hidden",
                    "OPACITY_ZERO" => "Element has opacity: 0",
                    _ => $"Element not visible: {result}"
                });
        }
        catch (Exception ex)
        {
            Assert.Fail(desc, ex.Message);
        }
    }

    public async Task AssertElementNotVisible(string selector, string? message = null)
    {
        var desc = message ?? $"Element not visible: {selector}";
        try
        {
            // Resolve semantic locators; if element not found, pass (not visible = doesn't exist)
            var resolved = await TryResolveLocatorOnce(selector);
            if (resolved == null)
            {
                Assert.Pass(desc);
                return;
            }
            var js = WrapWithDeepQuery($@"
                var el = deepQuery({JsonEscape(resolved)});
                if (!el) return 'NOT_FOUND';
                var rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return 'HIDDEN';
                var style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) return 'HIDDEN';
                return 'VISIBLE';
            ");
            var result = await RunJs(js);
            if (result != "VISIBLE")
                Assert.Pass(desc);
            else
                Assert.Fail(desc, "Element is visible");
        }
        catch (Exception ex)
        {
            Assert.Fail(desc, ex.Message);
        }
    }

    public async Task AssertElementText(string selector, string expected, string? message = null)
    {
        var desc = message ?? $"Element text equals: \"{Truncate(expected, 60)}\"";
        try
        {
            var actual = await GetText(selector);
            if (string.Equals(actual.Trim(), expected.Trim(), StringComparison.Ordinal))
                Assert.Pass(desc);
            else
                Assert.Fail(desc, $"Expected: \"{Truncate(expected, 80)}\"\n     Got: \"{Truncate(actual, 80)}\"");
        }
        catch (Exception ex)
        {
            Assert.Fail(desc, ex.Message);
        }
    }

    public async Task AssertElementContainsText(string selector, string expected, string? message = null)
    {
        var desc = message ?? $"Element contains: \"{Truncate(expected, 60)}\"";
        try
        {
            var actual = await GetText(selector);
            if (actual.Contains(expected, StringComparison.Ordinal))
                Assert.Pass(desc);
            else
                Assert.Fail(desc, $"Expected to contain: \"{Truncate(expected, 80)}\"\n     In: \"{Truncate(actual, 80)}\"");
        }
        catch (Exception ex)
        {
            Assert.Fail(desc, ex.Message);
        }
    }

    public async Task AssertElementAttribute(string selector, string attribute, string expected, string? message = null)
    {
        var desc = message ?? $"Element [{attribute}] equals: \"{Truncate(expected, 50)}\"";
        try
        {
            var actual = await GetAttribute(selector, attribute);
            if (string.Equals(actual, expected, StringComparison.Ordinal))
                Assert.Pass(desc);
            else
                Assert.Fail(desc, $"Expected [{attribute}]: \"{Truncate(expected, 80)}\"\n     Got: \"{Truncate(actual, 80)}\"");
        }
        catch (Exception ex)
        {
            Assert.Fail(desc, ex.Message);
        }
    }

    public async Task AssertUrl(string expected, string? message = null)
    {
        var desc = message ?? $"URL contains: \"{Truncate(expected, 60)}\"";
        var actual = await GetCurrentUrl();
        if (actual.Contains(expected, StringComparison.OrdinalIgnoreCase))
            Assert.Pass(desc);
        else
            Assert.Fail(desc, $"Expected URL to contain: \"{Truncate(expected, 80)}\"\n     Got: \"{Truncate(actual, 80)}\"");
    }

    public async Task AssertTitle(string expected, string? message = null)
    {
        var desc = message ?? $"Title contains: \"{Truncate(expected, 60)}\"";
        var actual = await GetTitle();
        if (actual.Contains(expected, StringComparison.OrdinalIgnoreCase))
            Assert.Pass(desc);
        else
            Assert.Fail(desc, $"Expected title to contain: \"{Truncate(expected, 80)}\"\n     Got: \"{Truncate(actual, 80)}\"");
    }

    public async Task AssertElementCount(string selector, int expected, string? message = null)
    {
        var desc = message ?? $"Element count ({selector}) equals: {expected}";
        var actual = await Count(selector);
        if (actual == expected)
            Assert.Pass(desc);
        else
            Assert.Fail(desc, $"Expected: {expected}, Got: {actual}");
    }

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength) return value;
        return value[..(maxLength - 3)] + "...";
    }

    #endregion

    #region Dialog Handling

    /// <summary>
    /// Last dialog from in-memory state (postMessage / native handler). Safe when the gate is held or JS is frozen.
    /// </summary>
    public DialogInfo? GetDialogSnapshot() => ActiveTab.LastDialog;

    /// <summary>
    /// Get the most recent dialog that appeared (alert/confirm/prompt), or null if none.
    /// Prefers in-memory state; refreshes from the page when JavaScript is responsive.
    /// </summary>
    public async Task<DialogInfo?> GetDialog()
    {
        var snapshot = ActiveTab.LastDialog;
        try
        {
            var json = await RunJs("JSON.stringify(window.__trowserDialog && window.__trowserDialog.last)");
            if (string.IsNullOrEmpty(json) || json == "null")
                return snapshot;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            return new DialogInfo
            {
                Type = root.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                Message = root.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "",
                DefaultValue = root.TryGetProperty("defaultValue", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null
            };
        }
        catch
        {
            return snapshot;
        }
    }

    /// <summary>
    /// Configure how native dialogs (alert/confirm/prompt) are handled (in-memory; does not require JS).
    /// </summary>
    public void SetDialogHandling(bool accept = true, string? promptText = null)
    {
        ActiveTab.DialogAccept = accept;
        ActiveTab.DialogPromptText = promptText;
    }

    /// <summary>
    /// Configure how native dialogs (alert/confirm/prompt) are handled.
    /// By default, dialogs are auto-accepted (confirm returns true, prompt returns default value).
    /// Call before the action that triggers the dialog.
    /// </summary>
    public async Task HandleDialog(bool accept = true, string? promptText = null)
    {
        SetDialogHandling(accept, promptText);
        await TryApplyDialogConfigAsync();
    }

    internal async Task TryApplyDialogConfigAsync()
    {
        try
        {
            await ApplyDialogConfig();
        }
        catch
        {
            /* page may be frozen — in-memory DialogAccept still applies to ScriptDialogOpening */
        }
    }

    internal async Task ApplyDialogConfig()
    {
        var accept = ActiveTab.DialogAccept ? "true" : "false";
        var promptJs = ActiveTab.DialogPromptText != null ? JsonEscape(ActiveTab.DialogPromptText) : "null";
        await RunJs($"if(window.__trowserDialog){{window.__trowserDialog.accept={accept};window.__trowserDialog.promptText={promptJs}}} 'OK'");
    }

    /// <summary>
    /// Clear the last dialog record.
    /// </summary>
    public async Task DismissDialog()
    {
        ActiveTab.LastDialog = null;
        await TryClearDialogJsStateAsync();
    }

    /// <summary>Clear last dialog without requiring the automation gate or responsive JS.</summary>
    public void ClearDialogSnapshot()
    {
        ActiveTab.LastDialog = null;
        _ = TryClearDialogJsStateAsync();
    }

    private async Task TryClearDialogJsStateAsync()
    {
        try
        {
            await RunJs("window.__trowserDialog.last = null; 'OK'");
        }
        catch
        {
            /* best effort */
        }
    }

    #endregion
}
