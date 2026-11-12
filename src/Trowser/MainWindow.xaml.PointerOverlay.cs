using System.Text.Json;
using System.Windows.Threading;
using Trowser.Automation;
using Trowser.Pointers;

namespace Trowser;

/// <summary>
/// P2 wiring for the live pointer overlay (agent → human). Shows agent-authored pointers as numbered
/// badges in a borderless click-through window over the WebView. Rects are re-queried read-only via
/// <c>getBoundingClientRect</c> on a short timer (covers scroll and resize without mutating the page),
/// mapped page-CSS-px → overlay-DIP by <see cref="PointerCoordinateMapper"/>, and pointers that no
/// longer resolve are shown honestly as parked "stale" chips.
/// </summary>
public partial class MainWindow
{
    private PointerOverlayWindow? _pointerOverlay;
    private DispatcherTimer? _pointerOverlayTimer;
    private bool _pointerOverlayRefreshing;
    private int _lastAgentPointerCount;

    // Only pointers created after this moment are shown. Navigation advances it so a fresh round of
    // agent pointing starts numbering from 1 and pre-navigation pointers don't reappear.
    private DateTime _pointerOverlayEpoch = DateTime.MinValue;

    // When set (Journal "Show me"), render exactly these pointers — any author, ignoring the epoch.
    private HashSet<string>? _pointerOverlayFocusIds;

    /// <summary>
    /// Subscribe once at startup so a fresh agent pointer auto-reveals the overlay. Agent→human
    /// signalling shouldn't require the human to know a keyboard shortcut — when the agent points,
    /// the human should just see it. Manual dismissal is respected: only a genuinely new agent
    /// pointer re-shows the overlay.
    /// </summary>
    private void WirePointerOverlayAutoShow()
    {
        try { _lastAgentPointerCount = _pointerStore.GetAll(author: PointerAuthors.Agent).Count; }
        catch { _lastAgentPointerCount = 0; }
        _pointerStore.Changed += OnPointerStoreChangedForAutoShow;
    }

    private void OnPointerStoreChangedForAutoShow() => Dispatcher.BeginInvoke(() =>
    {
        int count;
        try { count = _pointerStore.GetAll(author: PointerAuthors.Agent).Count; }
        catch { return; }
        var isNew = count > _lastAgentPointerCount;
        _lastAgentPointerCount = count;
        if (isNew && _pointerOverlay == null)
            ShowPointerOverlay();
    });

    /// <summary>Ctrl+Shift+P — show/hide the agent pointer overlay.</summary>
    private void TogglePointerOverlay()
    {
        if (_pointerOverlay != null) HidePointerOverlay();
        else ShowPointerOverlay();
    }

    private void ShowPointerOverlay()
    {
        if (_pointerOverlay != null) return;
        try
        {
            _pointerOverlay = new PointerOverlayWindow(this, TabContentArea);
            _pointerOverlay.Show();
            _pointerStore.Changed += OnPointerStoreChangedForOverlay;

            _pointerOverlayTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            _pointerOverlayTimer.Tick += (_, _) => _ = RefreshPointerOverlayAsync();
            _pointerOverlayTimer.Start();

            _ = RefreshPointerOverlayAsync();
            StatusText.Text = "Pointer overlay ON — agent pointers shown (Ctrl+Shift+P to toggle)";
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Pointer overlay show failed: {ex.Message}");
            _pointerOverlay = null;
        }
    }

    /// <summary>Journal "Show me": navigate-time overlay of specific pointer ids (human or agent).</summary>
    private void ShowSpecificPointers(IEnumerable<string> pointerIds)
    {
        _pointerOverlayFocusIds = new HashSet<string>(pointerIds.Where(id => !string.IsNullOrWhiteSpace(id)),
            StringComparer.OrdinalIgnoreCase);
        if (_pointerOverlayFocusIds.Count == 0)
        {
            _pointerOverlayFocusIds = null;
            return;
        }
        if (_pointerOverlay == null)
            ShowPointerOverlay();
        else
            _ = RefreshPointerOverlayAsync();
    }

    private void HidePointerOverlay(bool announce = true)
    {
        _pointerOverlayFocusIds = null;
        _pointerOverlayTimer?.Stop();
        _pointerOverlayTimer = null;
        _pointerStore.Changed -= OnPointerStoreChangedForOverlay;
        if (_pointerOverlay != null)
        {
            try { _pointerOverlay.Close(); } catch { /* best effort */ }
            _pointerOverlay = null;
        }
        if (announce)
            StatusText.Text = "Pointer overlay OFF";
    }

    /// <summary>
    /// Dismiss the overlay because the pointed-at page is going away (navigation, incl. SPA route
    /// changes). Silent — the caller is already updating the status line for the navigation. The
    /// pointers themselves stay in the store; the overlay re-appears only when the agent points again.
    /// </summary>
    internal void DismissPointerOverlayForNavigation()
    {
        // Advance the epoch on every navigation (even if the overlay wasn't open) so the next round of
        // agent pointing renders only the new pointers, numbered from 1.
        _pointerOverlayEpoch = DateTime.Now;
        if (_pointerOverlay != null)
            HidePointerOverlay(announce: false);
    }

    // May fire from an API/worker thread when the agent creates a pointer — marshal to the UI thread.
    private void OnPointerStoreChangedForOverlay() =>
        Dispatcher.BeginInvoke(() => { _ = RefreshPointerOverlayAsync(); });

    private async Task RefreshPointerOverlayAsync()
    {
        var overlay = _pointerOverlay;
        if (overlay == null) return;
        if (_pointerOverlayRefreshing) return; // don't overlap JS batches (timer + Changed can coincide)
        _pointerOverlayRefreshing = true;
        try
        {
            var ctx = _automationContext;
            if (ctx == null) { overlay.SetMarkers(Array.Empty<PointerMarker>()); return; }

            int? tabId = null;
            try { tabId = ctx.GetActiveTabIndex(); } catch { /* best effort */ }

            List<Pointer> pointers;
            if (_pointerOverlayFocusIds != null)
            {
                pointers = _pointerOverlayFocusIds
                    .Select(id => _pointerStore.Get(id))
                    .Where(p => p != null)
                    .Cast<Pointer>()
                    .ToList();
            }
            else
            {
                pointers = _pointerStore.GetAll(author: PointerAuthors.Agent)
                    .Where(p => p.CreatedAt > _pointerOverlayEpoch)
                    .ToList();
                if (tabId.HasValue)
                    pointers = pointers.Where(p => p.TabId == null || p.TabId == tabId.Value).ToList();
            }

            double zoom = 1.0;
            try { zoom = ctx.ActiveTab.WebView.ZoomFactor; } catch { /* default */ }

            var viewportW = TabContentArea.ActualWidth;
            var viewportH = TabContentArea.ActualHeight;

            var markers = new List<PointerMarker>(pointers.Count);
            var number = 0;
            foreach (var p in pointers)
            {
                number++;
                var isAbsence = p.Kind == PointerKinds.Absence;

                // Anchorless pointer (text-only agent handoff): nothing to resolve on the page, so show
                // it as a numbered note rather than hunting for a rect and calling it "stale".
                var anchorless = string.IsNullOrWhiteSpace(p.Anchors.Selector) && p.Anchors.Rect == null;
                if (anchorless)
                {
                    markers.Add(new PointerMarker(number, p.Id, p.Kind, p.Caption,
                        default, Stale: false, OffScreen: false, IsAbsence: isAbsence, Note: true));
                    continue;
                }

                var (found, rectCss) = await ResolvePointerRectAsync(ctx, p);
                if (!found || rectCss == null)
                {
                    markers.Add(new PointerMarker(number, p.Id, p.Kind, p.Caption,
                        default, Stale: true, OffScreen: false, IsAbsence: isAbsence));
                    continue;
                }

                var local = PointerCoordinateMapper.PageToOverlay(rectCss.Value, zoom);
                var onScreen = PointerCoordinateMapper.IntersectsViewport(local, viewportW, viewportH);
                markers.Add(new PointerMarker(number, p.Id, p.Kind, p.Caption,
                    local, Stale: false, OffScreen: !onScreen, IsAbsence: isAbsence));
            }

            overlay.SetMarkers(markers);
        }
        catch (Exception ex) { TrowserLog.Warn($"Pointer overlay refresh failed: {ex.Message}"); }
        finally { _pointerOverlayRefreshing = false; }
    }

    private async Task<(bool found, MapRect? rect)> ResolvePointerRectAsync(AutomationContext ctx, Pointer p)
    {
        try
        {
            var script = BuildOverlayRectScript(p);
            if (script == null) return (false, null);
            var raw = await ctx.ExecuteJs(script);
            if (string.IsNullOrWhiteSpace(raw)) return (false, null);
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            if (!root.TryGetProperty("found", out var f) || f.ValueKind != JsonValueKind.True)
                return (false, null);
            if (!root.TryGetProperty("rect", out var r) || r.ValueKind != JsonValueKind.Object)
                return (false, null);
            return (true, new MapRect(GetNum(r, "x"), GetNum(r, "y"), GetNum(r, "width"), GetNum(r, "height")));
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Pointer rect resolve failed: {ex.Message}");
            return (false, null);
        }
    }

    /// <summary>Read-only rect query: selector first, else the stored rect centre adjusted for scroll
    /// drift via <c>elementsFromPoint</c>. Mirrors the server's resolve script but never mutates the DOM.</summary>
    private static string? BuildOverlayRectScript(Pointer p)
    {
        var selector = p.Anchors.Selector;
        var rect = p.Anchors.Rect;
        var ci = System.Globalization.CultureInfo.InvariantCulture;

        if (!string.IsNullOrWhiteSpace(selector))
        {
            var sel = EscapePointerLiteral(selector);
            return "(function(){try{var el=document.querySelector(" + sel + ");"
                + "if(!el)return JSON.stringify({found:false});"
                + "var r=el.getBoundingClientRect();"
                + "return JSON.stringify({found:true,rect:{x:r.x,y:r.y,width:r.width,height:r.height}});"
                + "}catch(e){return JSON.stringify({found:false});}})()";
        }

        if (rect != null)
        {
            var cx = (rect.X + rect.Width / 2).ToString(ci);
            var cy = (rect.Y + rect.Height / 2).ToString(ci);
            var sx = rect.ScrollX.ToString(ci);
            var sy = rect.ScrollY.ToString(ci);
            return "(function(){try{"
                + "var dx=(window.scrollX-" + sx + ");var dy=(window.scrollY-" + sy + ");"
                + "var els=document.elementsFromPoint(" + cx + "-dx," + cy + "-dy);"
                + "if(!els||!els.length)return JSON.stringify({found:false});"
                + "var r=els[0].getBoundingClientRect();"
                + "return JSON.stringify({found:true,rect:{x:r.x,y:r.y,width:r.width,height:r.height}});"
                + "}catch(e){return JSON.stringify({found:false});}})()";
        }

        return null;
    }
}
