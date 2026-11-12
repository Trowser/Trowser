using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows.Media.Imaging;
using Trowser.Automation;
using Trowser.Pointers;
using Trowser.Recording;

namespace Trowser;

/// <summary>
/// P1 pointer handoff: the <c>!?</c> snip flow and the checkpoint-bounded handoff payload that
/// replaces the old "last 10 GUI actions" trail. Freezing a page bitmap the instant <c>!?</c> is
/// pressed both freezes the moment and gives an exact, DPI-independent mapping from the drawn
/// rectangle back to page coordinates.
/// </summary>
public partial class MainWindow
{
    /// <summary>Viewport metrics captured alongside the frozen bitmap, used to map bitmap px → CSS px.</summary>
    private sealed record ViewportMetrics(double InnerWidth, double InnerHeight, double ScrollX, double ScrollY);

    /// <summary>
    /// Entry point for <c>!?</c> / Ctrl+Shift+L. Captures a frozen page bitmap, lets the tester snip a
    /// rectangle, creates a human-authored pointer with that frozen crop, then reveals the AI Assistant
    /// prefilled with the checkpoint-bounded handoff payload (never auto-sent).
    /// </summary>
    private async Task OpenStrangeMomentAsync()
    {
        var ctx = _automationContext;
        if (ctx == null)
        {
            IsChatPanelVisible = true;
            ChatPanelControl.PrefillStrangeMoment(BuildHandoffText(null, pointer: null, note: null));
            return;
        }

        // Try to capture the page. If there is no live page (or capture fails), degrade to the
        // text-only prefill so !? always does something useful.
        byte[]? pngBytes = null;
        try { pngBytes = await ctx.ScreenshotToBytes(); }
        catch (Exception ex) { TrowserLog.Warn($"Strange-moment capture failed: {ex.Message}"); }

        if (pngBytes == null || pngBytes.Length == 0)
        {
            IsChatPanelVisible = true;
            ChatPanelControl.PrefillStrangeMoment(BuildHandoffText(ctx, pointer: null, note: null));
            return;
        }

        var frozen = DecodePng(pngBytes);
        var metrics = await TryGetViewportMetricsAsync(ctx);

        var snip = new SnipOverlayWindow(this, frozen);
        var ok = snip.ShowDialog();
        if (ok != true || snip.Result == null)
            return; // tester cancelled — do nothing

        // Text-only handoff (no rectangle drawn): there is no "this/here" to anchor, so we skip the
        // pointer and just hand the note plus the checkpoint trail to the agent.
        if (!snip.Result.HasRegion)
        {
            IsChatPanelVisible = true;
            ChatPanelControl.PrefillStrangeMoment(BuildHandoffText(ctx, pointer: null, note: snip.Result.Caption));
            return;
        }

        var pointer = await CreateHumanPointerFromSnipAsync(ctx, frozen, snip.Result, metrics);

        IsChatPanelVisible = true;
        ChatPanelControl.PrefillStrangeMoment(BuildHandoffText(ctx, pointer, note: pointer.Caption));
    }

    /// <summary>Build a human pointer from a snip result: map to CSS px, resolve the element, freeze the crop.</summary>
    private async Task<Pointer> CreateHumanPointerFromSnipAsync(AutomationContext ctx, BitmapSource frozen, SnipResult snip, ViewportMetrics? metrics)
    {
        var anchors = new PointerAnchors();
        var kind = snip.IsAbsence ? PointerKinds.Absence : PointerKinds.Element;

        // Map the bitmap rect → CSS viewport rect when we know the page's pixel scale.
        double cssCx = 0, cssCy = 0;
        var haveCss = false;
        if (metrics != null && metrics.InnerWidth > 0 && metrics.InnerHeight > 0)
        {
            var scaleX = frozen.PixelWidth / metrics.InnerWidth;
            var scaleY = frozen.PixelHeight / metrics.InnerHeight;
            if (scaleX > 0 && scaleY > 0)
            {
                var cssX = snip.BitmapRect.X / scaleX;
                var cssY = snip.BitmapRect.Y / scaleY;
                var cssW = snip.BitmapRect.Width / scaleX;
                var cssH = snip.BitmapRect.Height / scaleY;
                anchors.Rect = new PointerRect
                {
                    X = Math.Round(cssX, 1),
                    Y = Math.Round(cssY, 1),
                    Width = Math.Round(cssW, 1),
                    Height = Math.Round(cssH, 1),
                    ScrollX = metrics.ScrollX,
                    ScrollY = metrics.ScrollY
                };
                cssCx = cssX + cssW / 2;
                cssCy = cssY + cssH / 2;
                haveCss = true;
            }
        }

        // Resolve the element under the box centre (unless it's an absence). Best effort:
        // blocked in safe mode or on a dead page — the frozen crop is the reliable record.
        if (!snip.IsAbsence && haveCss)
        {
            try
            {
                var script = RunScriptContextScript.BuildElementAtPointScript((int)Math.Round(cssCx), (int)Math.Round(cssCy));
                var raw = await ctx.ExecuteJs(script);
                var el = ContextMenuElementInfo.ParseFromJson(raw);
                if (el != null && el.HasTarget)
                {
                    anchors.Selector = string.IsNullOrWhiteSpace(el.Selector) ? null : el.Selector;
                    anchors.Text = string.IsNullOrWhiteSpace(el.Text) ? null : el.Text;
                    var choice = ChoosePointerLocator(el);
                    if (choice.HasTarget)
                    {
                        anchors.Locator = LocatorBuilder.ToScriptExpression(choice, EscapePointerLiteral);
                        anchors.LocatorKind = choice.Kind.ToString().ToLowerInvariant();
                    }
                }
                else
                {
                    // Nothing interactive there — a region observation rather than an element.
                    if (!snip.IsAbsence) kind = PointerKinds.Region;
                }
            }
            catch (Exception ex) { TrowserLog.Warn($"Snip element resolution failed: {ex.Message}"); }
        }

        var cropPath = SaveSnipCrop(frozen, snip.BitmapRect);

        string? url = null;
        try { url = await ctx.GetCurrentUrl(); } catch { /* best effort */ }

        int? tabId = null;
        try { tabId = ctx.GetActiveTabIndex(); } catch { /* best effort */ }
        if (anchors.Ref < 0) anchors.RefGeneration = SafePointerRefGeneration(ctx);

        var pointer = new Pointer
        {
            Kind = kind,
            Anchors = anchors,
            Caption = snip.Caption,
            Author = PointerAuthors.Human,
            TabId = tabId,
            Url = url,
            CheckpointId = _pointerStore.LatestCheckpoint?.Id,
            CropPath = cropPath,
            Status = PointerStatuses.Resolved
        };

        _pointerStore.Add(pointer);
        try
        {
            var entry = _sessionLogger.LogPointer(PointerAuthors.Human, kind, snip.Caption, pointer.Id, url);
            pointer.JournalIndex = entry.Index;
        }
        catch (Exception ex) { TrowserLog.Warn($"Pointer journal log failed: {ex.Message}"); }

        return pointer;
    }

    /// <summary>
    /// Build the checkpoint-bounded handoff payload: an optional pointer's technical anchor, the GUI
    /// actions and console/network errors since the most recent checkpoint (or a capped tail when none
    /// exists), and — last, so it reads as the actual ask to the agent — the human's own words
    /// (<paramref name="note"/>). Replaces <c>BuildStrangeMomentTrail</c>'s arbitrary "last 10 GUI actions".
    /// </summary>
    private string BuildHandoffText(AutomationContext? ctx, Pointer? pointer, string? note)
    {
        var sb = new StringBuilder();

        // Pointer context first (the "this/here"): the anchor, crop, url — but NOT the caption, which
        // is the human's message and belongs at the end with the rest of what they want to say.
        if (pointer != null)
        {
            sb.AppendLine("Pointer I dropped:");
            var kindLabel = pointer.Kind == PointerKinds.Absence ? "absence (should be here, isn't)" : pointer.Kind;
            sb.AppendLine($"- {pointer.Id} [{kindLabel}]");
            if (!string.IsNullOrWhiteSpace(pointer.Anchors.Locator))
                sb.AppendLine($"  - target: {LocatorBuilder.Describe(ChoiceFromAnchors(pointer.Anchors))}");
            else if (!string.IsNullOrWhiteSpace(pointer.Anchors.Selector))
                sb.AppendLine($"  - target: {pointer.Anchors.Selector}");
            else if (pointer.Anchors.Rect != null)
                sb.AppendLine($"  - region: {Math.Round(pointer.Anchors.Rect.Width)}×{Math.Round(pointer.Anchors.Rect.Height)} at ({Math.Round(pointer.Anchors.Rect.X)}, {Math.Round(pointer.Anchors.Rect.Y)})");
            if (!string.IsNullOrWhiteSpace(pointer.CropPath))
                sb.AppendLine($"  - crop: {pointer.CropPath}");
            if (!string.IsNullOrWhiteSpace(pointer.Url))
                sb.AppendLine($"  - url: {pointer.Url}");
            sb.AppendLine();
        }

        var cp = _pointerStore?.LatestCheckpoint;
        var sinceLabel = cp != null
            ? $"since checkpoint {cp.Id}{(string.IsNullOrWhiteSpace(cp.Label) ? "" : $" ({cp.Label})")}"
            : "recent activity";

        if (_sessionLogger.IsLogging)
        {
            var actions = cp != null
                ? _sessionLogger.GetJournal(since: cp.JournalIndex, type: "action", source: "gui")
                : _sessionLogger.GetJournal(last: 15, type: "action", source: "gui");

            if (actions.Count > 0)
            {
                if (actions.Count > 15) actions = actions.GetRange(actions.Count - 15, 15);
                sb.AppendLine($"Actions ({sinceLabel}):");
                foreach (var entry in actions)
                {
                    var line = $"- {entry.Timestamp:HH:mm:ss} {entry.Summary}";
                    if (!string.IsNullOrWhiteSpace(entry.Details)) line += $" — {entry.Details}";
                    sb.AppendLine(line);
                }
                sb.AppendLine();
            }
        }

        if (ctx != null)
            AppendErrorsSince(ctx, sb, cp?.CreatedAt);

        var trail = sb.ToString().TrimEnd();

        // The human's words go last so the agent reads the context, then the actual ask. "Over to you"
        // reads as a handoff whether the note is a bug, a "this is odd", or a plain request.
        if (!string.IsNullOrWhiteSpace(note))
        {
            var body = new StringBuilder();
            if (trail.Length > 0) body.Append(trail).Append("\n\n");
            body.Append("Over to you:\n").Append(note!.Trim());
            return body.ToString();
        }

        return trail.Length == 0
            ? (_sessionLogger.IsLogging ? "Session log is on, but nothing notable recorded yet." : "Session log is off — no action trail.")
            : trail;
    }

    private void AppendErrorsSince(AutomationContext ctx, StringBuilder sb, DateTime? since)
    {
        try
        {
            var consoleErrors = ctx.GetConsoleErrors();
            if (since != null) consoleErrors = consoleErrors.FindAll(e => e.Timestamp >= since.Value);
            if (consoleErrors.Count > 0)
            {
                sb.AppendLine("Console errors:");
                foreach (var e in Tail(consoleErrors, 10))
                    sb.AppendLine($"- {e.Timestamp:HH:mm:ss} {Trim(e.Message, 200)}");
                sb.AppendLine();
            }

            var net = ctx.GetNetworkLog();
            var failed = net.FindAll(n => n.IsError && (since == null || n.Timestamp >= since.Value));
            if (failed.Count > 0)
            {
                sb.AppendLine("Failed requests:");
                foreach (var n in Tail(failed, 10))
                    sb.AppendLine($"- {n.Timestamp:HH:mm:ss} {n.Method} {n.StatusCode} {n.Path}");
                sb.AppendLine();
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"Handoff error trail failed: {ex.Message}"); }
    }

    /// <summary>
    /// Create a human-authored pointer from a right-click element (the shared basis for
    /// Send to Chat, Add to bug, and Element of interest — the P1 gesture consolidation).
    /// Captures an element crop unless one is supplied, resolves a ref/locator, and journals it.
    /// </summary>
    private async Task<Pointer> CreateHumanPointerFromElementAsync(
        AutomationContext ctx, ContextMenuElementInfo el, string kind, string? caption,
        string? existingCropPath = null, int? knownRef = null)
    {
        var anchors = new PointerAnchors
        {
            Selector = string.IsNullOrWhiteSpace(el.Selector) ? null : el.Selector,
            Text = string.IsNullOrWhiteSpace(el.Text) ? null : el.Text,
            RefGeneration = SafePointerRefGeneration(ctx)
        };

        var choice = ChoosePointerLocator(el);
        if (choice.HasTarget)
        {
            anchors.Locator = LocatorBuilder.ToScriptExpression(choice, EscapePointerLiteral);
            anchors.LocatorKind = choice.Kind.ToString().ToLowerInvariant();
        }

        if (knownRef.HasValue)
        {
            anchors.Ref = knownRef.Value;
        }
        else if (anchors.Selector != null)
        {
            try
            {
                await ctx.GetInteractiveElements();
                anchors.Ref = await ctx.FindRefForSelectorAsync(anchors.Selector) ?? -1;
            }
            catch (Exception ex) { TrowserLog.Warn($"Pointer ref resolution failed: {ex.Message}"); }
        }

        var cropPath = existingCropPath;
        if (cropPath == null && anchors.Selector != null)
        {
            try { cropPath = SaveBytesCrop(await ctx.ScreenshotElementToBytes(anchors.Selector, padding: 4)); }
            catch (Exception ex) { TrowserLog.Warn($"Pointer element crop failed: {ex.Message}"); }
        }

        string? url = null;
        try { url = await ctx.GetCurrentUrl(); } catch { /* best effort */ }
        int? tabId = null;
        try { tabId = ctx.GetActiveTabIndex(); } catch { /* best effort */ }

        var pointer = new Pointer
        {
            Kind = kind,
            Anchors = anchors,
            Caption = caption,
            Author = PointerAuthors.Human,
            TabId = tabId,
            Url = url,
            CheckpointId = _pointerStore.LatestCheckpoint?.Id,
            CropPath = cropPath,
            Status = PointerStatuses.Resolved
        };

        _pointerStore.Add(pointer);
        try
        {
            var entry = _sessionLogger.LogPointer(PointerAuthors.Human, kind, caption, pointer.Id, url);
            pointer.JournalIndex = entry.Index;
        }
        catch (Exception ex) { TrowserLog.Warn($"Pointer journal log failed: {ex.Message}"); }

        return pointer;
    }

    // ----- helpers -----

    private static string? SaveBytesCrop(byte[] bytes)
    {
        try
        {
            if (bytes == null || bytes.Length == 0) return null;
            var dir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, $"pointer-{DateTime.Now:yyyyMMdd_HHmmss_fff}.png");
            File.WriteAllBytes(path, bytes);
            return path;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Pointer crop save failed: {ex.Message}");
            return null;
        }
    }

    private async Task<ViewportMetrics?> TryGetViewportMetricsAsync(AutomationContext ctx)
    {
        try
        {
            var raw = await ctx.ExecuteJs(
                "JSON.stringify({iw:window.innerWidth, ih:window.innerHeight, sx:window.scrollX, sy:window.scrollY})");
            if (string.IsNullOrWhiteSpace(raw)) return null;
            using var doc = JsonDocument.Parse(raw);
            var r = doc.RootElement;
            return new ViewportMetrics(
                GetNum(r, "iw"), GetNum(r, "ih"), GetNum(r, "sx"), GetNum(r, "sy"));
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Viewport metrics query failed: {ex.Message}");
            return null;
        }
    }

    private string? SaveSnipCrop(BitmapSource frozen, System.Windows.Rect rect)
    {
        try
        {
            var x = (int)Math.Round(rect.X);
            var y = (int)Math.Round(rect.Y);
            var w = (int)Math.Round(rect.Width);
            var h = (int)Math.Round(rect.Height);
            if (w <= 0 || h <= 0) return null;
            x = Math.Max(0, Math.Min(frozen.PixelWidth - 1, x));
            y = Math.Max(0, Math.Min(frozen.PixelHeight - 1, y));
            w = Math.Min(frozen.PixelWidth - x, w);
            h = Math.Min(frozen.PixelHeight - y, h);
            if (w <= 0 || h <= 0) return null;

            var cropped = new CroppedBitmap(frozen, new System.Windows.Int32Rect(x, y, w, h));
            var dir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, $"pointer-{DateTime.Now:yyyyMMdd_HHmmss_fff}.png");

            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(cropped));
            using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
            encoder.Save(fs);
            return path;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Snip crop save failed: {ex.Message}");
            return null;
        }
    }

    private static BitmapSource DecodePng(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        var img = new BitmapImage();
        img.BeginInit();
        img.CacheOption = BitmapCacheOption.OnLoad;
        img.StreamSource = ms;
        img.EndInit();
        img.Freeze();
        return img;
    }

    private static int SafePointerRefGeneration(AutomationContext ctx)
    {
        try { return ctx.RefGeneration; } catch { return -1; }
    }

    private static LocatorChoice ChoosePointerLocator(ContextMenuElementInfo el) =>
        LocatorBuilder.Choose(
            tag: el.Tag,
            testId: string.IsNullOrWhiteSpace(el.TestId) ? null : el.TestId,
            role: string.IsNullOrWhiteSpace(el.Role) ? null : el.Role,
            label: string.IsNullOrWhiteSpace(el.Label) ? null : el.Label,
            text: string.IsNullOrWhiteSpace(el.Text) ? null : el.Text,
            selector: string.IsNullOrWhiteSpace(el.Selector) ? null : el.Selector,
            placeholder: string.IsNullOrWhiteSpace(el.Placeholder) ? null : el.Placeholder,
            textUnique: true,
            isClickable: true);

    private static LocatorChoice ChoiceFromAnchors(PointerAnchors a)
    {
        if (!Enum.TryParse<LocatorKind>(a.LocatorKind, ignoreCase: true, out var kind))
            return LocatorChoice.None;
        // Re-render from the stored expression's meaning; we only need Describe(), so pass values through.
        return kind switch
        {
            LocatorKind.Role => new LocatorChoice(kind, a.Text ?? a.Selector, a.Text),
            _ => new LocatorChoice(kind, a.Selector ?? a.Text, null)
        };
    }

    private static string EscapePointerLiteral(string value) =>
        "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static double GetNum(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static string Trim(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "…");

    private static List<T> Tail<T>(List<T> list, int n) =>
        list.Count <= n ? list : list.GetRange(list.Count - n, n);
}
