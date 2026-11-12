using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.Sse;
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
private async Task<object> ToolSnapshot(JsonElement args)
    {
        var fullText = GetBool(args, "fullText");
        var selectorFilter = GetString(args, "selector");
        var frame = GetString(args, "frame");
        var snapshot = await _context.GetSnapshot(fullText, selectorFilter, frame);
        snapshot["refGeneration"] = _context.RefGeneration;

        // Strip pageText to save tokens -- LLMs can use browser_page_text when needed
        snapshot.Remove("pageText");

        // Visible filter: default true (hide ref:-1 elements). Pass visible=false to include hidden.
        bool visibleOnly = GetOptOutBool(args, "visible");

        if (snapshot.TryGetValue("interactiveElements", out var elemObj)
            && elemObj is List<Dictionary<string, object>> elements)
        {
            HashSet<int>? refsInContainer = null;
            if (!string.IsNullOrEmpty(selectorFilter))
                refsInContainer = await _context.GetRefsInContainer(selectorFilter, elements);

            var limitFilter = GetInt(args, "limit", 0);
            var fullElements = GetBool(args, "fullElements");
            var compactFormat = string.Equals(GetString(args, "format"), "compact", StringComparison.OrdinalIgnoreCase);

            var filtered = InteractiveSnapshotFilter.Apply(
                elements,
                visibleOnly,
                limitFilter,
                fullElements,
                GetString(args, "tag"),
                GetString(args, "type"),
                GetString(args, "q"),
                selectorFilter,
                refsInContainer,
                compactFormat);

            snapshot["interactiveElements"] = filtered.Elements
                .Select(e =>
                {
                    var slim = new Dictionary<string, object>(e);
                    slim.Remove("selector");
                    slim.Remove("visible");
                    slim.Remove("inViewport");
                    return slim;
                })
                .ToList();
            if (filtered.Truncated)
            {
                snapshot["interactiveElementsTruncated"] = true;
                snapshot["interactiveElementsTotal"] = filtered.TotalBeforeLimit;
                snapshot["interactiveElementsHint"] =
                    "More elements exist. Use fullElements, limit, q, selector, or browser_state_enrich.";
            }
            if (filtered.CompactLines != null)
                snapshot["interactiveElementsLines"] = filtered.CompactLines;
        }

        var json = JsonSerializer.Serialize(snapshot, CompactJson);
        return TextContent(json);
    }

private async Task<object> ToolStateRefresh()
    {
        // Small delay to let in-flight DOM mutations settle
        await Task.Delay(100);

        var snapshot = await _context.GetSnapshot(false, null);
        snapshot["refGeneration"] = _context.RefGeneration;
        snapshot.Remove("pageText");
        snapshot["refreshed"] = true;

        // Strip selectors from interactive elements for compactness (same as ToolSnapshot)
        if (snapshot.TryGetValue("interactiveElements", out var elemObj)
            && elemObj is List<Dictionary<string, object>> elements)
        {
            var compact = elements
                .Where(e => e.TryGetValue("visible", out var v)
                    && (v is true || (v is JsonElement je && je.ValueKind == JsonValueKind.True)))
                .Select(e =>
                {
                    var slim = new Dictionary<string, object>(e);
                    slim.Remove("selector");
                    slim.Remove("visible");
                    return slim;
                })
                .ToList();
            snapshot["interactiveElements"] = compact;
        }

        var json = JsonSerializer.Serialize(snapshot, CompactJson);
        return TextContent(json);
    }

private object ToolDiffState(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object)
            return ErrorContent("Provide JSON object with 'before' and 'after' refGeneration integers.");

        var before = GetInt(args, "before", -1);
        var after = GetInt(args, "after", -1);
        if (before < 0 || after < 0)
            return ErrorContent("Provide non-negative 'before' and 'after' refGeneration values from browser_snapshot.");

        int? tabIndex = null;
        if (args.TryGetProperty("tabIndex", out var ti) && ti.ValueKind == JsonValueKind.Number)
        {
            tabIndex = ti.GetInt32();
            if (tabIndex < 0)
                return ErrorContent("tabIndex must be >= 0.");
        }

        var diff = _context.BuildRefGenerationDiff(before, after, out var error, tabIndex);
        if (diff == null)
            return ErrorContent(error ?? "Failed to build diff.");

        var json = JsonSerializer.Serialize(diff, CompactJson);
        return TextContent(json);
    }

private async Task<object> ToolNavigate(JsonElement args)
    {
        var action = GetString(args, "action")?.Trim().ToLowerInvariant();
        if (action is "back" or "forward")
        {
            try
            {
                if (action == "back")
                    await _context.GoBack();
                else
                    await _context.GoForward();
                var currentUrl = await _context.GetCurrentUrl();
                var title = await _context.GetTitle();
                return TextContent($"History {action}: {currentUrl}\nTitle: {title}");
            }
            catch (InvalidOperationException ex)
            {
                return ErrorContent(ex.Message);
            }
        }

        if (!string.IsNullOrEmpty(action))
            return ErrorContent("Invalid 'action'. Use 'back', 'forward', or omit and pass 'url'.");

        var url = GetString(args, "url");
        if (string.IsNullOrEmpty(url))
            return ErrorContent("Provide 'url' to navigate, or 'action': 'back' / 'forward' for session history.");

        var reload = GetBool(args, "reload", false);
        var ignoreCert = GetBool(args, "ignoreCertificateErrors", false);
        var beforeUrl = await _context.GetCurrentUrl();
        var targetUrl = url.Trim();
        if (!targetUrl.Contains("://") && !targetUrl.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            targetUrl = "https://" + targetUrl;

        string? freshGetNote = null;
        if (reload && AutomationContext.UrlEquivalentForNavigate(beforeUrl, targetUrl))
            await _context.Reload();
        else if (!reload && AutomationContext.UrlEquivalentForNavigate(beforeUrl, targetUrl))
        {
            _context.ActiveTab.LastSameUrlFreshGetDocumentReloaded = null;
            await _context.NavigateFreshGetAsync(targetUrl, ignoreCert);
            var reloaded = _context.ActiveTab.LastSameUrlFreshGetDocumentReloaded;
            freshGetNote = reloaded == false
                ? "\nFresh-get: same URL, document not replaced (no-op)."
                : reloaded == true
                    ? "\nFresh-get: document replaced."
                    : null;
        }
        else
            await _context.Navigate(url, reload, ignoreCert);

        var u = await _context.GetCurrentUrl();
        var t = await _context.GetTitle();
        return TextContent($"Navigated to {u}\nTitle: {t}{freshGetNote}");
    }

private async Task<object> ToolForceNavigate(JsonElement args)
    {
        var url = GetString(args, "url");
        if (string.IsNullOrWhiteSpace(url))
            return ErrorContent("Provide 'url' (e.g. 'about:blank').");

        var terminateScripts = true;
        if (args.TryGetProperty("terminateScripts", out var ts))
        {
            if (ts.ValueKind == JsonValueKind.True) terminateScripts = true;
            else if (ts.ValueKind == JsonValueKind.False) terminateScripts = false;
            else
                return ErrorContent("terminateScripts must be a boolean.");
        }

        try
        {
            await _context.ForceNavigateAsync(url.Trim(), terminateScripts);
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
        catch (TimeoutException ex)
        {
            return ErrorContent(ex.Message);
        }

        if (ForceNavigateBypassGate && AfterSuccessfulForceNavigateAsync != null)
            await AfterSuccessfulForceNavigateAsync();

        var u = await _context.GetCurrentUrl();
        var t = await _context.GetTitle();
        return TextContent($"Force-navigated (CDP Runtime.terminateExecution + Page.navigate) to {u}\nTitle: {t}");
    }

private async Task<object> ToolGoBack()
    {
        try
        {
            await _context.GoBack();
            var url = await _context.GetCurrentUrl();
            var title = await _context.GetTitle();
            return TextContent($"Went back to {url}\nTitle: {title}");
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolGoForward()
    {
        try
        {
            await _context.GoForward();
            var url = await _context.GetCurrentUrl();
            var title = await _context.GetTitle();
            return TextContent($"Went forward to {url}\nTitle: {title}");
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolClick(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref' (from browser_snapshot), 'selector' (CSS), or a semantic locator (role+name, label, text, placeholder).");

        var button = GetString(args, "button") ?? "left";
        var clickCount = GetInt(args, "clickCount", 1);
        if (clickCount < 1) clickCount = 1;

        var before = await _context.CapturePageState();
        await _context.Click(selector, button, clickCount);
        await Task.Delay(100);
        var after = await _context.CapturePageState();
        var changes = AutomationContext.DiffPageState(before, after);

        var clickDesc = (button, clickCount) switch
        {
            ("right", _) => "Right-clicked",
            ("middle", _) => "Middle-clicked",
            (_, 2) => "Double-clicked",
            (_, > 2) => $"Clicked {clickCount}x",
            _ => "Clicked"
        };

        if (changes != null && changes.Count > 0)
        {
            var changesJson = JsonSerializer.Serialize(changes, CompactJson);
            return TextContent($"{clickDesc} {Fmt(selector)}\nChanges: {changesJson}");
        }
        return TextContent($"{clickDesc} {Fmt(selector)}");
    }

    private async Task<object> ToolClickAt(JsonElement args)
    {
        if (!args.TryGetProperty("x", out var xEl) || xEl.ValueKind != JsonValueKind.Number
            || !args.TryGetProperty("y", out var yEl) || yEl.ValueKind != JsonValueKind.Number)
            return ErrorContent("Provide viewport coordinates 'x' and 'y' (CSS pixels from the page top-left).");

        var x = xEl.GetDouble();
        var y = yEl.GetDouble();
        var button = GetString(args, "button") ?? "left";
        var clickCount = GetInt(args, "clickCount", 1);
        if (clickCount < 1) clickCount = 1;

        try
        {
            var before = await _context.CapturePageState();
            await _context.ClickAt(x, y, button, clickCount);
            await Task.Delay(100);
            var after = await _context.CapturePageState();
            var changes = AutomationContext.DiffPageState(before, after);
            var payload = new { x, y, button, clickCount, method = "cdp-viewport", changes };
            return TextContent(JsonSerializer.Serialize(payload, CompactJson));
        }
        catch (ArgumentException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolDrag(JsonElement args)
    {
        try
        {
            var frame = GetString(args, "frame");
            string? fromSel = null;
            string? toSel = null;

            if (args.TryGetProperty("from", out var fromEl) && fromEl.ValueKind == JsonValueKind.Object)
            {
                if (!string.IsNullOrEmpty(frame) && !fromEl.TryGetProperty("frame", out _))
                {
                    var dict = new Dictionary<string, JsonElement>();
                    foreach (var p in fromEl.EnumerateObject())
                        dict[p.Name] = p.Value.Clone();
                    dict["frame"] = JsonSerializer.SerializeToElement(frame);
                    using var doc = JsonDocument.Parse(JsonSerializer.Serialize(dict));
                    fromSel = ResolveElement(doc.RootElement);
                }
                else
                    fromSel = ResolveElement(fromEl);
            }
            else
            {
                var flat = new Dictionary<string, object?>();
                if (args.TryGetProperty("fromRef", out var fr) && fr.ValueKind == JsonValueKind.Number)
                    flat["ref"] = fr.GetInt32();
                if (args.TryGetProperty("fromSelector", out var fs) && fs.ValueKind == JsonValueKind.String)
                    flat["selector"] = fs.GetString();
                if (!string.IsNullOrEmpty(frame)) flat["frame"] = frame;
                using var doc = JsonDocument.Parse(JsonSerializer.Serialize(flat));
                fromSel = ResolveElement(doc.RootElement);
            }

            if (args.TryGetProperty("to", out var toEl) && toEl.ValueKind == JsonValueKind.Object)
            {
                if (!string.IsNullOrEmpty(frame) && !toEl.TryGetProperty("frame", out _))
                {
                    var dict = new Dictionary<string, JsonElement>();
                    foreach (var p in toEl.EnumerateObject())
                        dict[p.Name] = p.Value.Clone();
                    dict["frame"] = JsonSerializer.SerializeToElement(frame);
                    using var doc = JsonDocument.Parse(JsonSerializer.Serialize(dict));
                    toSel = ResolveElement(doc.RootElement);
                }
                else
                    toSel = ResolveElement(toEl);
            }
            else
            {
                var flat = new Dictionary<string, object?>();
                if (args.TryGetProperty("toRef", out var tr) && tr.ValueKind == JsonValueKind.Number)
                    flat["ref"] = tr.GetInt32();
                if (args.TryGetProperty("toSelector", out var ts) && ts.ValueKind == JsonValueKind.String)
                    flat["selector"] = ts.GetString();
                if (!string.IsNullOrEmpty(frame)) flat["frame"] = frame;
                using var doc = JsonDocument.Parse(JsonSerializer.Serialize(flat));
                toSel = ResolveElement(doc.RootElement);
            }

            if (fromSel == null || toSel == null)
                return ErrorContent("Provide from and to elements (nested objects or fromRef/toRef / fromSelector/toSelector).");

            var steps = GetInt(args, "steps", 10);
            bool? html5 = null;
            if (args.TryGetProperty("html5", out var h5) &&
                h5.ValueKind is JsonValueKind.True or JsonValueKind.False)
                html5 = h5.GetBoolean();
            var path = await _context.Drag(fromSel, toSel, steps, html5: html5);
            return TextContent($"Dragged {Fmt(fromSel)} → {Fmt(toSel)} ({steps} steps, path={path})");
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException or ArgumentException)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolType(JsonElement args)
    {
        var selector = ResolveTypeElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator (label, byText, placeholder, ...) to identify the input element.");

        var html = GetString(args, "html");
        // Accept value (MCP-native) or text (REST-shaped) as typed content.
        var value = GetString(args, "value") ?? GetString(args, "text");
        if (value == null && html == null)
            return ErrorContent("Provide 'value' or 'text' (content to type), or 'html' for rich content.");

        await _context.Type(selector, value ?? "", html: html);
        var desc = html != null
            ? $"Typed HTML into {Fmt(selector)}"
            : $"Typed \"{value}\" into {Fmt(selector)}";
        return TextContent(desc);
    }

private async Task<object> ToolUpload(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the file input.");

        var paths = GetStringArray(args, "paths");
        var single = GetString(args, "path");
        if (paths is not { Count: > 0 } && !string.IsNullOrWhiteSpace(single))
            paths = new List<string> { single! };

        var tempFiles = new List<string>();
        try
        {
            if (args.TryGetProperty("base64", out var b64El) && b64El.ValueKind == JsonValueKind.String)
            {
                var b64 = b64El.GetString();
                if (string.IsNullOrWhiteSpace(b64))
                    return ErrorContent("Field 'base64' must be non-empty when provided.");

                byte[] bytes;
                try
                {
                    bytes = Convert.FromBase64String(b64);
                }
                catch (FormatException)
                {
                    return ErrorContent("Invalid base64 in 'base64' field.");
                }

                var name = GetString(args, "fileName") ?? "upload.bin";
                var ext = Path.GetExtension(name);
                if (string.IsNullOrEmpty(ext))
                    ext = ".bin";
                var tmp = Path.Combine(Path.GetTempPath(), "trowser-upload-" + Guid.NewGuid().ToString("N") + ext);
                await File.WriteAllBytesAsync(tmp, bytes);
                tempFiles.Add(tmp);
                paths = new List<string> { tmp };
            }

            if (paths is not { Count: > 0 })
                return ErrorContent("Provide 'path', 'paths', or 'base64' (+ optional 'fileName').");

            var timeout = GetInt(args, "timeout", 0);
            var submit = GetBool(args, "submit", false);

            await _context.SetFileInput(selector, paths, timeout > 0 ? timeout : null, submit);

            var note = tempFiles.Count > 0 ? " (temp file from base64 removed)" : "";
            return TextContent(
                $"Assigned {paths.Count} file(s) to {Fmt(selector)}{note}" + (submit ? " and submitted form." : "."));
        }
        finally
        {
            foreach (var t in tempFiles)
            {
                try
                {
                    File.Delete(t);
                }
                catch
                {
                    // best-effort
                }
            }
        }
    }

private async Task<object> ToolSelect(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the select element.");

        var value = GetString(args, "value");
        if (value == null)
            return ErrorContent("Missing required field: value");

        await _context.Select(selector, value);
        var actual = await _context.GetSelectState(selector);
        var actualJson = JsonSerializer.Serialize(actual, CompactJson);
        return TextContent($"Selected \"{value}\" in {Fmt(selector)}\nResult: {actualJson}");
    }

private async Task<object> ToolHover(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the element.");

        await _context.Hover(selector);
        return TextContent($"Hovered over {Fmt(selector)}");
    }

private async Task<object> ToolPressKey(JsonElement args)
    {
        var key = GetString(args, "key");
        if (string.IsNullOrEmpty(key))
            return ErrorContent("Missing required field: key");

        var selector = ResolveElement(args);
        string[]? modifiers = null;
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty("modifiers", out var modArr) &&
            modArr.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var item in modArr.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String)
                    list.Add(item.GetString()!);
            modifiers = list.ToArray();
        }

        await _context.PressKey(key, selector, modifiers);
        var target = selector != null ? Fmt(selector) : "active element";
        var mods = modifiers is { Length: > 0 } ? $" with [{string.Join("+", modifiers)}]" : "";
        return TextContent($"Pressed {key}{mods} on {target}");
    }

private async Task<object> ToolScroll(JsonElement args)
    {
        var direction = GetString(args, "direction") ?? "down";
        var scrollIntoView = GetBool(args, "scrollIntoView");
        var timeout = GetInt(args, "timeout");
        var selector = ResolveElement(args);

        await _context.Scroll(selector, direction, scrollIntoView, timeout > 0 ? timeout : null);

        if (scrollIntoView && selector != null)
            return TextContent($"Scrolled {Fmt(selector)} into view");
        return TextContent($"Scrolled {selector ?? "page"} {direction}");
    }

private async Task<object> ToolScreenshot(JsonElement args)
    {
        var selector = args.ValueKind == JsonValueKind.Object ? ResolveElement(args) : null;

        var purposeRaw = args.ValueKind == JsonValueKind.Object ? GetString(args, "purpose") : null;
        var purpose = string.IsNullOrWhiteSpace(purposeRaw) ? "journal" : purposeRaw.Trim().ToLowerInvariant();
        var inspect = purpose switch
        {
            "journal" or "log" or "attach" => false,
            "inspect" or "look" or "view" => true,
            _ => (bool?)null
        };
        if (inspect == null)
            return ErrorContent("Invalid 'purpose'. Use 'journal' (save + attach to journal, no image in the result) or 'inspect' (return image to look at).");

        var inspectImage = inspect.Value;
        var format = inspectImage ? "jpeg" : "png";
        var quality = 80;
        if (args.ValueKind == JsonValueKind.Object)
        {
            var formatArg = GetString(args, "format");
            if (formatArg?.Equals("jpeg", StringComparison.OrdinalIgnoreCase) == true)
                format = "jpeg";
            else if (formatArg?.Equals("png", StringComparison.OrdinalIgnoreCase) == true)
                format = "png";
            if (args.TryGetProperty("quality", out var qualProp) && qualProp.ValueKind == JsonValueKind.Number)
                quality = Math.Clamp(qualProp.GetInt32(), 1, 100);
        }

        var ext = format == "jpeg" ? "jpg" : "png";
        var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
        var filePath = Path.Combine(_screenshotDir, $"trowser-{timestamp}.{ext}");
        Directory.CreateDirectory(_screenshotDir);

        byte[] bytes;
        if (selector != null)
        {
            int padding = 0;
            if (args.TryGetProperty("padding", out var padProp) && padProp.ValueKind == JsonValueKind.Number)
                padding = Math.Clamp(padProp.GetInt32(), 0, 200);

            bytes = await _context.ScreenshotElementToBytes(selector, padding, format, quality);
        }
        else
        {
            bytes = await _context.ScreenshotToBytes(format, quality);
        }

        await File.WriteAllBytesAsync(filePath, bytes);

        var label = selector != null ? "element" : "full page";
        var note = args.ValueKind == JsonValueKind.Object ? GetString(args, "note") : null;
        var journalLine = "";
        var logger = SessionLogger;
        if (logger != null)
        {
            var entry = logger.LogScreenshot(filePath, "api", note);
            journalLine = $" Journal #{entry.Index} ({entry.Type}).";
        }
        else if (!inspectImage)
        {
            journalLine = " Journal not attached (session logger unavailable); file saved.";
        }

        var text = $"Screenshot saved to: {filePath} ({bytes.Length:N0} bytes, {format.ToUpperInvariant()} {label}).{journalLine}";
        if (!inspectImage)
            text += " Image bytes omitted (purpose=journal). Pass purpose:'inspect' to look at the image.";

        if (!inspectImage)
            return TextContent(text);

        var base64 = Convert.ToBase64String(bytes);
        var mimeType = format == "jpeg" ? "image/jpeg" : "image/png";
        return new
        {
            content = new object[]
            {
                new { type = "text", text },
                new { type = "image", data = base64, mimeType }
            }
        };
    }

private async Task<object> ToolScreenshotCompare(JsonElement args)
    {
        if (!args.TryGetProperty("before", out var beforeProp) ||
            string.IsNullOrEmpty(beforeProp.GetString()))
            return ErrorContent("Missing required 'before' parameter (file path from browser_take_screenshot)");

        var beforeStr = beforeProp.GetString()!;
        byte[] beforeBytes;
        try
        {
            beforeBytes = ExportPathGuard.IsExistingLocalFile(beforeStr)
                ? await File.ReadAllBytesAsync(beforeStr)
                : Convert.FromBase64String(beforeStr);
        }
        catch (FormatException)
        {
            return ErrorContent($"Invalid 'before' value: file not found and not valid base64 data: {beforeStr}");
        }

        byte[] afterBytes;
        if (args.TryGetProperty("after", out var afterProp) &&
            !string.IsNullOrEmpty(afterProp.GetString()))
        {
            var afterStr = afterProp.GetString()!;
            try
            {
                afterBytes = ExportPathGuard.IsExistingLocalFile(afterStr)
                    ? await File.ReadAllBytesAsync(afterStr)
                    : Convert.FromBase64String(afterStr);
            }
            catch (FormatException)
            {
                return ErrorContent($"Invalid 'after' value: file not found and not valid base64 data: {afterStr}");
            }
        }
        else
        {
            afterBytes = await _context.ScreenshotToBytes();
        }

        int threshold = 30;
        if (args.TryGetProperty("threshold", out var threshProp) && threshProp.ValueKind == JsonValueKind.Number)
            threshold = Math.Clamp(threshProp.GetInt32(), 0, 255);

        var result = await _context.CompareScreenshots(beforeBytes, afterBytes, threshold);

        var diffBase64 = Convert.ToBase64String(result.DiffImagePng);
        var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
        var diffPath = Path.Combine(_screenshotDir, $"trowser-diff-{timestamp}.png");
        Directory.CreateDirectory(_screenshotDir);
        await File.WriteAllBytesAsync(diffPath, result.DiffImagePng);

        string summary;
        if (result.DiffPercent == 0)
            summary = $"Visual diff: MATCH — no pixel differences detected (threshold: {threshold}). " +
                       $"Image: {result.Width}×{result.Height}. Diff saved to: {diffPath}";
        else
            summary = $"Visual diff: {result.DiffPercent:F1}% changed ({result.ChangedPixels:N0} of {result.TotalPixels:N0} pixels). " +
                       $"Image: {result.Width}×{result.Height}. Threshold: {threshold}. Diff saved to: {diffPath}";

        return new
        {
            content = new object[]
            {
                new { type = "text", text = summary },
                new { type = "image", data = diffBase64, mimeType = "image/png" }
            }
        };
    }

private async Task<object> ToolGetText(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the element.");

        var text = await _context.GetText(selector);
        return TextContent(text);
    }

private async Task<object> ToolGetProperty(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the element.");

        var property = GetString(args, "property");
        if (string.IsNullOrEmpty(property))
            return ErrorContent("Missing required field: property");

        var value = await _context.GetProperty(selector, property);
        return TextContent($"{property} = {value}");
    }

private async Task<object> ToolExtract(JsonElement args)
    {
        var selector = GetString(args, "selector");
        if (string.IsNullOrEmpty(selector))
            return ErrorContent("Missing required field: selector");

        Dictionary<string, string>? fields = null;
        if (args.TryGetProperty("fields", out var fieldsProp) && fieldsProp.ValueKind == JsonValueKind.Object)
        {
            fields = new Dictionary<string, string>();
            foreach (var kv in fieldsProp.EnumerateObject())
                fields[kv.Name] = kv.Value.GetString() ?? kv.Value.ToString();
        }

        var limit = GetInt(args, "limit", 0);
        var data = await _context.Extract(selector, fields, limit);

        var json = JsonSerializer.Serialize(data, CompactJson);
        return TextContent($"Extracted {data.Count} items from \"{selector}\":\n{json}");
    }

private async Task<object> ToolFind(JsonElement args)
    {
        var text = GetString(args, "text");
        if (string.IsNullOrEmpty(text))
            return ErrorContent("Missing required field: text");

        var caseSensitive = GetBool(args, "caseSensitive");
        var regex = GetBool(args, "regex");
        var highlight = GetBool(args, "highlight");
        var visibleOnly = GetOptOutBool(args, "visibleOnly");
        int? scrollTo = args.ValueKind == JsonValueKind.Object
            && args.TryGetProperty("scrollTo", out var st) && st.ValueKind == JsonValueKind.Number
            ? st.GetInt32() : null;

        var result = await _context.FindText(text, caseSensitive, regex, scrollTo, highlight, visibleOnly);

        var matchCount = result.TryGetValue("matchCount", out var mc) ? mc : 0;
        var json = JsonSerializer.Serialize(result, CompactJson);
        return TextContent($"Found {matchCount} match(es) for \"{text}\":\n{json}");
    }

private async Task<object> ToolFindClear()
    {
        await _context.ClearFindHighlights();
        return TextContent("Find highlights cleared.");
    }

private async Task<object> ToolPageText()
    {
        var text = await _context.GetPageText();
        return TextContent(text);
    }

private async Task<object> ToolPageTextAll()
    {
        var text = await _context.GetAllPageText();
        return TextContent(text);
    }

private async Task<object> ToolPageTextScreenReader()
    {
        var text = await _context.GetScreenReaderTexts();
        return TextContent(text);
    }

private async Task<object> ToolPageSource()
    {
        var source = await _context.GetPageSource();
        return TextContent(source);
    }

private async Task<object> ToolExecuteJs(JsonElement args)
    {
        var tabTarget = ResolveTabTargetFromArgs(args, out var tabErr);
        if (tabErr != null)
            return ErrorContent(tabErr);

        var script = GetString(args, "script");
        if (string.IsNullOrEmpty(script))
            script = GetString(args, "expression");
        if (string.IsNullOrEmpty(script))
            script = GetString(args, "code");
        if (string.IsNullOrEmpty(script))
            return ErrorContent("Missing required field: script (aliases: expression, code)");

        var timeout = GetInt(args, "timeout", 30_000);
        var frame = GetString(args, "frame");
        try
        {
            return await _context.InvokeOnTabAsync(tabTarget, async () =>
            {
                var result = string.IsNullOrWhiteSpace(frame)
                    ? await _context.ExecuteJs(script, timeout)
                    : await _context.ExecuteJsInFrame(frame, script, timeout);
                return TextContent(result);
            });
        }
        catch (TimeoutException ex)
        {
            return ErrorContent(ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent($"JavaScript error: {ex.Message}");
        }
    }

private async Task<object> ToolAccessibility(JsonElement args)
    {
        var level = GetString(args, "level") ?? "AA";
        var selector = GetString(args, "selector");

        var result = await _context.CheckAccessibility(level, selector);
        return TextContent(result.Format(includeNodes: true));
    }

private async Task<object> ToolTabOrder(JsonElement args)
    {
        var options = new TabOrderOptions
        {
            Selector = GetString(args, "selector"),
            StartSelector = GetString(args, "startSelector") ?? GetString(args, "start"),
            AutoDetectScope = GetBool(args, "autoDetectScope", true),
            StrictScope = GetBool(args, "strictScope", true),
            MaxSteps = GetInt(args, "maxSteps", 150),
            CheckPositiveTabIndex = GetBool(args, "checkPositiveTabIndex", true),
            CheckSkipped = GetBool(args, "checkSkipped", true),
            CheckReadingOrder = GetBool(args, "checkReadingOrder", true),
            CheckFocusTrap = GetBool(args, "checkFocusTrap", true),
            CheckShiftTabConsistency = GetBool(args, "checkShiftTabConsistency", true),
            ExpectedOrder = GetStringArray(args, "expectedOrder")
        };

        var result = await _context.CheckTabOrder(options);
        var includeSteps = GetBool(args, "includeSteps", true);
        var payload = new
        {
            result.IsClean,
            result.Url,
            result.Title,
            result.ScopeSelector,
            result.FocusContextKind,
            result.FocusContextLabel,
            result.ScopeAutoDetected,
            result.FocusableCount,
            result.ForwardCycleComplete,
            result.BackwardChecked,
            result.ShiftTabConsistencyChecked,
            result.BackwardCycleComplete,
            result.ShiftTabConsistent,
            result.ExpectedOrderMatched,
            forwardStepCount = result.ForwardSteps.Count,
            backwardStepCount = result.BackwardSteps.Count,
            issueCount = result.Issues.Count,
            issues = result.Issues.Select(i => new
            {
                category = i.Category,
                severity = i.Severity.ToString().ToLowerInvariant(),
                message = i.Message,
                selector = i.Selector,
                label = i.Label,
                stepIndex = i.StepIndex
            }),
            forwardSteps = includeSteps ? result.ForwardSteps : null,
            backwardSteps = includeSteps ? result.BackwardSteps : null,
            summary = result.Format(includeSteps: false)
        };
        return TextContent(JsonSerializer.Serialize(payload, CompactJson));
    }

private async Task<object> ToolPerformance()
    {
        var result = await _context.CheckPerformance();
        return TextContent(result.Format(includeNavigation: true, includeResources: true));
    }

private async Task<object> ToolResourceSnapshot(JsonElement args)
    {
        var snapshot = await _context.CheckResourceSnapshot(GetBool(args, "rememberBaseline"));
        return TextContent(ResourceSnapshotFormatter.Format(snapshot));
    }

private async Task<object> ToolResourceCompare(JsonElement args)
    {
        ResourceSnapshot? baseline = null;
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty("baseline", out var baselineEl) &&
            baselineEl.ValueKind == JsonValueKind.Object)
        {
            using var doc = JsonDocument.Parse(baselineEl.GetRawText());
            baseline = TrowserApiServer.ParseResourceSnapshotFromBody(new JsonBody(doc));
        }
        else if (GetBool(args, "useRememberedBaseline"))
        {
            baseline = _context.RememberedResourceBaseline;
        }

        if (baseline == null)
        {
            throw new InvalidParamsException(
                "Provide \"baseline\" from browser_resource_snapshot, or useRememberedBaseline: true after a snapshot with rememberBaseline: true.");
        }

        var options = new ResourceProbeOptions
        {
            GcBeforeFinal = GetBool(args, "gcBeforeFinal", true),
            SettleMs = GetInt(args, "settleMs", 500),
            GrowthThresholdPercent = GetDouble(args, "growthThresholdPercent", 10),
            ListenerGrowthThreshold = GetInt(args, "listenerGrowthThreshold", 50),
            NodeGrowthThreshold = GetInt(args, "nodeGrowthThreshold", 100),
        };

        var result = await _context.CompareResourceUsage(baseline, options);
        return TextContent(result.Format());
    }

private async Task<object> ToolResourceProbe(JsonElement args)
    {
        var options = new ResourceProbeOptions
        {
            Actions = ParseInterrupterActions(args),
            Iterations = GetInt(args, "iterations", 5),
            GcBetweenIterations = GetBool(args, "gcBetweenIterations", true),
            SettleMs = GetInt(args, "settleMs", 500),
            ReloadBetweenIterations = GetBool(args, "reloadBetweenIterations"),
            GrowthThresholdPercent = GetDouble(args, "growthThresholdPercent", 10),
            ListenerGrowthThreshold = GetInt(args, "listenerGrowthThreshold", 50),
            NodeGrowthThreshold = GetInt(args, "nodeGrowthThreshold", 100),
        };

        if (ResourceProbe.RequiresActiveSafetyMode(options))
        {
            var gateError = SafetyGate.RequireActive(args,
                "Resource probe replays click/type actions that may trigger server-side effects");
            if (gateError != null)
                throw new InvalidParamsException(gateError.Value.Message);
        }

        ResourceProbeResult result;
        try
        {
            result = await _context.RunResourceProbe(options);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidParamsException(ex.Message);
        }

        return TextContent(result.Format());
    }

private async Task<object> ToolAttackSurface(JsonElement args)
    {
        var body = JsonBody.FromToolArguments(args);
        var includeParameters = body.GetBool("includeParameters", true);
        var includeAuth = body.GetBool("includeAuth", true);
        var includeResponsePatterns = body.GetBool("includeResponsePatterns", true);
        var hostFilter = body.GetString("host");
        var includeDataUrls = body.GetBool("includeDataUrls", false);
        var spaMode = body.GetBool("spaMode", false);
        var checkSecurityTxt = body.GetBool("checkSecurityTxt", true);

        var entries = _context.Network.Entries;
        if (entries.Count == 0 && !spaMode)
        {
            return ErrorContent(
                "No network traffic captured. Browse the target application first to populate the network log, " +
                "or set spaMode: true to map inputs/links from the live page (GET /api/state) without network data.");
        }

        var mapper = new AttackSurfaceMapper();
        var result = mapper.Analyze(
            entries.Count == 0 ? new List<NetworkEntry>() : entries,
            includeParameters, includeAuth, includeResponsePatterns, hostFilter, includeDataUrls);

        var networkLogEmpty = entries.Count == 0;
        result.NetworkLogEmpty = networkLogEmpty;
        if (spaMode)
        {
            var interactive = await _context.GetInteractiveElements();
            var formCount = await _context.GetHtmlFormCountAsync();
            var pageUrl = await _context.GetCurrentUrl();
            var pageTitle = await _context.GetTitle();
            result.SpaRuntime = AttackSurfaceMapper.BuildSpaRuntimeSurface(
                interactive, formCount, pageUrl, pageTitle);
            result.Source = networkLogEmpty ? "dom-only" : "network-log+dom";
        }
        else
        {
            result.Source = "network-log";
        }

        var navUrl = await _context.GetCurrentUrl();

        if (body.GetBool("includeApiEnrichment", true))
        {
            await AttackSurfaceEnrichment.RunAsync(
                result,
                _context,
                entries.Count == 0 ? new List<NetworkEntry>() : entries.ToList(),
                navUrl,
                new AttackSurfaceEnrichment.Options(
                    IncludeOpenApiFromNetwork: body.GetBool("includeOpenApiFromNetwork", true),
                    IncludeOpenApiProbes: body.GetBool("includeOpenApiProbes", true),
                    IncludeJsBundleHints: body.GetBool("includeJsBundleHints", true),
                    IncludeDevArtifactProbes: body.GetBool("includeDevArtifactProbes", true),
                    MaxProbeOrigins: Math.Clamp(body.GetInt("maxProbeOrigins", 6), 1, 20),
                    MaxScripts: Math.Clamp(body.GetInt("maxJsScripts", 24), 1, 80),
                    MaxBytesPerScript: Math.Clamp(body.GetInt("maxJsBundleBytesPerFile", 524_288), 8192, 2_000_000),
                    MaxJsHintPaths: Math.Clamp(body.GetInt("maxJsHintPaths", 200), 16, 2000),
                    HttpTimeoutMs: Math.Clamp(body.GetInt("enrichmentHttpTimeoutMs", 12_000), 3_000, 60_000),
                    MaxWordPressRestRoutes: Math.Clamp(body.GetInt("maxWordPressRestRoutes", 8000), 64, 50_000)),
                CancellationToken.None);

            if (result.Enrichment is { Enabled: true })
                result.Source += "+api-discovery";
        }

        if (checkSecurityTxt)
        {
            result.SecurityTxt =
                await Security.SecurityTxtProbe.CheckCurrentDocumentHostAsync(
                    entries.Count == 0 ? new List<NetworkEntry>() : entries.ToList(),
                    navUrl);
        }

        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolTraceInput(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Input tracing") is { } gateError)
            return ErrorContent(gateError);

        var jb = JsonBody.FromToolArguments(args);
        if (!TraceInputRequestParser.TryParse(jb, out var options, out var batchPayloads, out var parseError))
            return ErrorContent(parseError ?? "Invalid request");

        var tracer = new Security.InputTracer(_context);

        if (options.AutoBypass && batchPayloads == null)
        {
            var result = await tracer.TraceWithAutoBypassAsync(options);
            return TextContent(result.Format());
        }

        if (batchPayloads != null && batchPayloads.Count > 0)
        {
            var result = await tracer.TraceBatchAsync(batchPayloads, options with { AutoBypass = false });
            return TextContent(result.Format());
        }

        var single = await tracer.TraceAsync(options);
        return TextContent(single.Format());
    }

private async Task<object> ToolAuthzRoleMatrix(JsonElement args)
    {
        List<string>? identities = null;
        if (args.TryGetProperty("identities", out var idEl) && idEl.ValueKind == JsonValueKind.Array)
        {
            identities = idEl.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!)
                .ToList();
        }

        if (identities == null || identities.Count < 2)
            return ErrorContent("Field 'identities' is required: array of at least two captured identity names.");

        IdentityStore = IdentityStore ?? new IdentityStore();
        List<AttackSurfaceEndpoint>? surface = null;
        if (GetBool(args, "discoverFromAttackSurface", true))
        {
            var map = new AttackSurfaceMapper().Analyze(
                _context.Network.Entries, includeParameters: true, includeAuth: true,
                includeResponsePatterns: true, hostFilter: GetString(args, "host"));
            surface = map.Endpoints;
        }

        List<string>? endpoints = null;
        if (args.TryGetProperty("endpoints", out var ep) && ep.ValueKind == JsonValueKind.Array)
        {
            endpoints = ep.EnumerateArray()
                .Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!)
                .ToList();
        }

        var result = await AuthzRoleMatrixService.RunAsync(_context, IdentityStore,
            new AuthzRoleMatrixService.MatrixOptions
            {
                Identities = identities,
                Endpoints = endpoints,
                AttackSurface = surface,
                IncludeAdminEndpoints = GetBool(args, "includeAdminEndpoints", true),
                MaxEndpoints = GetInt(args, "maxEndpoints", 20),
                TimeoutMs = GetInt(args, "timeoutMs", 15000)
            });
        return TextContent(JsonSerializer.Serialize(result, CompactJson));
    }

private async Task<object> ToolWebSocketSend(JsonElement args)
    {
        var connectionId = GetInt(args, "connectionId", 0);
        var message = GetString(args, "message");
        if (connectionId <= 0 || string.IsNullOrEmpty(message))
            return ErrorContent("Required: connectionId (int), message (string).");

        var result = await WebSocketJsBridge.SendAsync(_context, connectionId, message);
        if (!result.Ok)
            return ErrorContent(result.Error ?? "WebSocket send failed.");
        return TextContent(JsonSerializer.Serialize(new { ok = true, hookId = result.HookId, url = result.Url }, CompactJson));
    }

private async Task<object> ToolWebSocketClose(JsonElement args)
    {
        var connectionId = GetInt(args, "connectionId", 0);
        if (connectionId <= 0)
            return ErrorContent("Required: connectionId (int).");

        int? code = args.TryGetProperty("code", out var codeEl) && codeEl.ValueKind == JsonValueKind.Number
            ? codeEl.GetInt32()
            : null;
        var result = await WebSocketJsBridge.CloseAsync(_context, connectionId, code, GetString(args, "reason"));
        if (!result.Ok)
            return ErrorContent(result.Error ?? "WebSocket close failed.");
        return TextContent(JsonSerializer.Serialize(new { ok = true, hookId = result.HookId }, CompactJson));
    }

private async Task<object> ToolVpxExport(JsonElement args)
    {
        var profile = GetString(args, "profile") ?? "compact";

        string? baseUrl = null;
        try { baseUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var exported = VpxSessionIo.Export(_context, SessionLogger, profile, baseUrl);
        return TextContent(exported.Json);
    }

private Task<object> ToolVpxImport(JsonElement args)
    {
        if (args.TryGetProperty("action", out var actionEl) &&
            actionEl.GetString()?.Equals("clear", StringComparison.OrdinalIgnoreCase) == true)
        {
            _context.ClearVpxSessionState();
            return Task.FromResult<object>(TextContent("{\"cleared\":true,\"dedupReset\":true}"));
        }

        var doc = args.TryGetProperty("document", out var docEl) ? docEl : args;
        if (doc.ValueKind != JsonValueKind.Object)
            return Task.FromResult<object>(ErrorContent("VPX document object required."));

        var mode = GetString(args, "mode") ?? "merge";
        try
        {
            var result = VpxImportService.ImportDocument(_context, doc, mode);
            return Task.FromResult<object>(TextContent(JsonSerializer.Serialize(result, CompactJson)));
        }
        catch (InvalidOperationException ex)
        {
            return Task.FromResult<object>(ErrorContent(ex.Message));
        }
    }

private Task<object> ToolVpxClear(JsonElement args)
    {
        _context.ClearVpxSessionState();
        return Task.FromResult<object>(TextContent("{\"cleared\":true,\"dedupReset\":true}"));
    }

private async Task<object> ToolFirewallTest(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Firewall testing injects scripts and modifies page state") is { } gateError)
            return ErrorContent(gateError);

        HashSet<string>? tests = null;
        if (args.TryGetProperty("tests", out var testsEl) && testsEl.ValueKind == JsonValueKind.Array)
            tests = testsEl.EnumerateArray()
                .Where(a => a.ValueKind == JsonValueKind.String)
                .Select(a => a.GetString()!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var verbose = GetBool(args, "verbose");
        var probes = GetStringArray(args, "probes");
        var tester = new Security.FirewallTester(_context);
        var result = await tester.RunAsync(tests, verbose, probes);
        var payload = FirewallApiPayload.Build(result, verbose);
        return TextContent(JsonSerializer.Serialize(payload, CompactJson));
    }

private async Task<object> ToolValidateHtml()
    {
        var result = await _context.CheckHtml();
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolSeo()
    {
        var result = await _context.RunSeoAuditAsync();
        return TextContent(result.Format());
    }

private async Task<object> ToolCheckLinks(JsonElement args)
    {
        var scope = GetString(args, "scope") ?? "anchors";
        var external = GetBool(args, "external", true);
        var timeoutMs = GetInt(args, "timeoutMs", 5000);
        var concurrency = GetInt(args, "concurrency", 10);
        var delayMs = GetInt(args, "delayMs", 100);
        var checker = new LinkChecking.LinkChecker(_context);
        var result = await checker.RunAsync(scope, external, timeoutMs, concurrency, delayMs);
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolStructuredText()
    {
        var result = await _context.GetStructuredText();
        return TextContent(result.Format());
    }

private async Task<object> ToolConsistency()
    {
        var result = await _context.CheckConsistency();
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolThirdParty()
    {
        var result = await _context.CheckThirdParty();
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolCompatibility(JsonElement args)
    {
        int? minIos = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("minIos", out var iosProp) && iosProp.ValueKind == JsonValueKind.Number
            ? iosProp.GetInt32() : null;
        int? minAndroid = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("minAndroid", out var androidProp) && androidProp.ValueKind == JsonValueKind.Number
            ? androidProp.GetInt32() : null;

        var result = await _context.CheckCompatibility(minIos, minAndroid);
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolAuditAll(JsonElement args)
    {
        if (AuditAllPayloadBuilder == null)
            return ErrorContent("Audit-all is not available.");

        var body = JsonBody.FromToolArguments(args);
        var data = await AuditAllPayloadBuilder(body);
        var json = JsonSerializer.Serialize(data, CompactJson);
        return TextContent(json);
    }

private async Task<object> ToolSurpriseMe(JsonElement args)
    {
        if (SurpriseMeRunner == null)
            return ErrorContent("SurpriseMe is not available.");

        var data = await SurpriseMeRunner();
        var json = JsonSerializer.Serialize(data, CompactJson);
        return TextContent(json);
    }

private async Task<object> ToolMonkeyTest(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Monkey test") is { } gateError)
            return ErrorContent(gateError);

        await ShowBackendWarning("Monkey test starting — random actions may trigger server-side effects.");

        var options = new MonkeyTestOptions
        {
            Actions = GetInt(args, "actions", 500),
            Delay = GetInt(args, "delay", 20),
            Seed = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("seed", out _)
                ? GetInt(args, "seed", 0) : null
        };

        var result = await _context.RunMonkeyTest(options);
        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolMonkeyTrowser(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Monkey Trowser") is { } gateError)
            return ErrorContent(gateError);

        await ShowBackendWarning("Monkey Trowser starting — form fuzzing and element clicks may trigger server-side effects.");

        var options = new SmartTestOptions
        {
            FollowLinks = GetBool(args, "followLinks", true),
            FuzzForms = GetBool(args, "fuzzForms", true),
            MaxPages = GetInt(args, "maxPages", 10),
            MaxActionsPerPage = GetInt(args, "maxActionsPerPage", 100),
            Scope = GetString(args, "scope"),
        };

        var result = await _context.RunSmartMonkey(options);
        return TextContent(result.Format(includeDetails: true));
    }

private Task<object> ToolAttackForm(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAttackFormAsync);

private async Task<object> ToolInterrupter(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Interrupter fault-injection test") is { } gateError)
            return ErrorContent(gateError);

        await ShowBackendWarning("Interrupter test starting — page will reload multiple times to test fault handling.");

        var options = new Robustness.InterrupterOptions
        {
            Url = GetString(args, "url"),
            Method = GetString(args, "method"),
            Faults = GetStringArray(args, "faults"),
            MaxEndpoints = GetInt(args, "maxEndpoints", 20),
            MinRelevanceScore = args.TryGetProperty("minRelevanceScore", out _)
                ? GetInt(args, "minRelevanceScore", 0)
                : GetInt(args, "minScore", 0),
            MergeAttackSurface = GetBool(args, "mergeAttackSurface", true),
            WaitForIdle = GetBool(args, "waitForIdle"),
            CustomFaults = ParseCustomFaults(args),
            Actions = ParseInterrupterActions(args),
            AllowedHosts = GetStringArray(args, "allowedHosts"),
            CooldownMs = GetInt(args, "cooldownMs"),
            RestoreUrl = GetBool(args, "restoreUrl", true),
        };

        var result = await _context.RunInterrupterTest(options);

        var report = result.Format(includeDetails: true);
        if (result.LoginRedirectDetected)
        {
            report += $"\n\nWARNING: After restoration, the page redirected to a login page ({result.FinalUrl}). " +
                "The session was likely disrupted by fault injection. Re-authenticate to continue testing.";
        }
        if (result.RestoreError != null)
        {
            report += $"\n\nWARNING: Failed to restore original page: {result.RestoreError}";
        }

        return TextContent(report);
    }

private async Task<object> ToolFuzz(JsonElement args)
    {
        if (SafetyGate.RequireActive(args, "Request fuzzer") is { } gateError)
            return ErrorContent(gateError);

        await ShowBackendWarning("Request Fuzzer starting — sending fuzz payloads to the target server.");

        Robustness.FuzzerOptions options;
        try
        {
            options = ParseFuzzerOptionsFromMcp(args);
        }
        catch (ArgumentException ex)
        {
            return ErrorContent(ex.Message);
        }

        Robustness.FuzzerResult result;
        try
        {
            result = await _context.RunFuzzerTest(options);
        }
        catch (ArgumentException ex)
        {
            return ErrorContent(ex.Message);
        }

        return TextContent(result.Format(includeDetails: true));
    }

private async Task<object> ToolConsole(JsonElement args)
    {
        int? tabIdx = null;
        if (args.ValueKind == JsonValueKind.Object
            && args.TryGetProperty("tabIndex", out var ti)
            && ti.TryGetInt32(out var idx)
            && idx >= 0)
            tabIdx = idx;

        return await _context.InvokeOnTabAsync(tabIdx, () =>
        {
            var entries = _context.Console.Entries;
            if (entries.Count == 0)
                return Task.FromResult<object>(TextContent("No console messages."));

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Console messages ({entries.Count}):");
            foreach (var e in entries)
                sb.AppendLine($"  [{e.Level.ToString().ToLower()}] {e.Message}");
            return Task.FromResult<object>(TextContent(sb.ToString().TrimEnd()));
        });
    }

private object ToolConsoleClear()
    {
        _context.ClearConsoleLog();
        return TextContent("Console log cleared.");
    }

private object ToolNetworkClear()
    {
        _context.ClearNetworkLog();
        return TextContent("Network log cleared.");
    }

    private object ToolNetworkHar(JsonElement args)
    {
        var har = _context.ExportHar(
            includeHeaders: GetOptOutBool(args, "includeHeaders"),
            includeBodies: GetBool(args, "includeBodies") || GetBool(args, "includeBody"),
            urlContains: GetString(args, "url"),
            method: GetString(args, "method"),
            errorsOnly: GetBool(args, "errorsOnly"),
            pageOnly: GetBool(args, "pageOnly"));
        return TextContent(JsonSerializer.Serialize(har, CompactJson));
    }

    private object ToolDownloads()
    {
        var list = _context.GetDownloads().Select(e => new
        {
            id = e.Id,
            url = e.Url,
            suggestedFileName = e.SuggestedFileName,
            path = e.Path,
            state = e.State.ToString().ToLowerInvariant(),
            bytes = e.BytesReceived,
            mime = e.MimeType
        }).ToList();
        return TextContent(JsonSerializer.Serialize(new { count = list.Count, downloads = list }, CompactJson));
    }

    private async Task<object> ToolWaitForDownload(JsonElement args)
    {
        try
        {
            var entry = await _context.WaitForDownload(
                GetString(args, "fileNameContains"),
                GetInt(args, "timeout", 30000),
                GetInt(args, "afterId", 0));
            return TextContent(JsonSerializer.Serialize(new
            {
                id = entry.Id,
                url = entry.Url,
                suggestedFileName = entry.SuggestedFileName,
                path = entry.Path,
                state = entry.State.ToString().ToLowerInvariant(),
                bytes = entry.BytesReceived,
                mime = entry.MimeType
            }, CompactJson));
        }
        catch (TimeoutException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private object ToolAssertDownload(JsonElement args)
    {
        try
        {
            bool? exists = args.TryGetProperty("exists", out _) ? GetBool(args, "exists", true) : true;
            long? minBytes = args.TryGetProperty("minBytes", out var mb) && mb.ValueKind == JsonValueKind.Number
                ? mb.GetInt64() : null;
            var entry = _context.AssertDownload(
                fileNameContains: GetString(args, "fileNameContains"),
                mimeContains: GetString(args, "mime") ?? GetString(args, "mimeContains"),
                minBytes: minBytes,
                exists: exists);
            return TextContent($"Download OK: {entry.SuggestedFileName} ({entry.BytesReceived} bytes)");
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolClearAll(JsonElement args)
    {
        HashSet<string>? preserve = null;
        var preserveList = GetStringArray(args, "preserve");
        if (preserveList != null)
            preserve = new HashSet<string>(preserveList, StringComparer.OrdinalIgnoreCase);

        var result = await _context.ClearAll(preserve);
        return TextContent(result.Summary);
    }

private async Task<object> ToolClearSession(JsonElement args)
    {
        var clearCookies = GetBool(args, "clearCookies");
        var result = clearCookies
            ? await _context.ClearAll(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "storage" })
            : await _context.ClearSession();
        return TextContent(result.Summary + (clearCookies ? " (cookies cleared)" : ""));
    }

private async Task<object> ToolNetwork(JsonElement args)
    {
        int? tabIdx = null;
        if (args.ValueKind == JsonValueKind.Object
            && args.TryGetProperty("tabIndex", out var ti)
            && ti.TryGetInt32(out var idx)
            && idx >= 0)
            tabIdx = idx;

        return await _context.InvokeOnTabAsync(tabIdx, () =>
        {
        IEnumerable<NetworkEntry> entries = _context.Network.Entries;

        if (GetBool(args, "errorsOnly"))
            entries = entries.Where(e => e.IsError);
        var urlFilter = GetString(args, "url");
        if (!string.IsNullOrEmpty(urlFilter))
            entries = entries.Where(e => e.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase));
        var methodFilter = GetString(args, "method");
        if (!string.IsNullOrEmpty(methodFilter))
            entries = entries.Where(e => e.Method.Equals(methodFilter, StringComparison.OrdinalIgnoreCase));
        if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty("statusMin", out var minProp) && minProp.ValueKind == JsonValueKind.Number &&
            args.TryGetProperty("statusMax", out var maxProp) && maxProp.ValueKind == JsonValueKind.Number)
        {
            var lo = minProp.GetInt32();
            var hi = maxProp.GetInt32();
            entries = entries.Where(e => e.StatusCode >= lo && e.StatusCode <= hi);
        }
        else if (args.ValueKind == JsonValueKind.Object &&
            args.TryGetProperty("status", out var statusProp) &&
            statusProp.TryGetInt32(out var statusCode))
            entries = entries.Where(e => e.StatusCode == statusCode);
        var typeFilter = GetString(args, "type");
        if (!string.IsNullOrEmpty(typeFilter))
            entries = entries.Where(e => (e.ResourceType ?? "").Equals(typeFilter, StringComparison.OrdinalIgnoreCase));
        if (GetBool(args, "eventStream"))
            entries = entries.Where(e => e.IsEventStream);

        int? onlyId = null;
        if (args.ValueKind == JsonValueKind.Object
            && args.TryGetProperty("id", out var idProp)
            && idProp.TryGetInt32(out var parsedId)
            && parsedId >= 0)
        {
            onlyId = parsedId;
            entries = entries.Where(e => e.Id == parsedId);
        }

        // Exclude data: URLs by default — base64 images destroy agent context windows.
        var includeDataUrls = GetBool(args, "includeDataUrls");
        if (!includeDataUrls)
            entries = entries.Where(e => !e.Url.StartsWith("data:", StringComparison.OrdinalIgnoreCase));

        var list = entries.ToList();
        if (list.Count == 0)
        {
            var missing = onlyId is int missingId
                ? $"No network entry with id {missingId}. List entries with browser_network, then pass that id. REST: GET /api/network/{{id}}."
                : "No matching network requests.";
            return Task.FromResult<object>(TextContent(missing));
        }

        // Prefer Document/Fetch/XHR when no explicit type filter (agent-friendly default).
        if (string.IsNullOrEmpty(typeFilter) && !GetBool(args, "errorsOnly"))
        {
            list = list
                .OrderBy(e => e.ResourceType switch
                {
                    "Document" => 0,
                    "Fetch" or "XHR" => 1,
                    "Script" => 2,
                    _ => 3
                })
                .ThenBy(e => e.Timestamp)
                .ToList();
        }

        var summary = GetBool(args, "summary");
        var singleEntry = onlyId != null;
        var includeHeaders = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("includeHeaders", out _)
            ? GetBool(args, "includeHeaders")
            : singleEntry;
        var includeBody = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("includeBody", out _)
            ? GetBool(args, "includeBody")
            : singleEntry;
        var bodyMaxChars = args.ValueKind == JsonValueKind.Object && args.TryGetProperty("bodyMaxChars", out _)
            ? GetInt(args, "bodyMaxChars", 200)
            : singleEntry ? 0 : 200;
        var limit = singleEntry ? 0 : GetInt(args, "limit", 50);
        var maxUrlChars = GetInt(args, "maxUrlChars", 500);

        static string FmtUrl(string url, int maxChars)
        {
            if (string.IsNullOrEmpty(url) || maxChars <= 0 || url.Length <= maxChars) return url;
            if (url.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                return $"data:…({url.Length} chars omitted)";
            return url[..maxChars] + "…";
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Network requests: {list.Count} ({list.Count(e => e.IsError)} errors)");
        if (!singleEntry)
            sb.AppendLine("One entry with headers and captured body: pass id. REST: GET /api/network/{id}.");

        if (summary)
        {
            foreach (var e in list)
            {
                var status = e.StatusCode > 0 ? e.StatusCode.ToString() : "---";
                var err = e.IsError ? " [ERROR]" : "";
                var timing = e.DurationMs.HasValue ? $" {e.DurationMs.Value:F0}ms" : "";
                var cache = e.ServedFromCache ? " cache" : "";
                var src = e.ResponseSource is "network" or "" ? "" : $" [{e.ResponseSource}]";
                var reqLen = e.RequestBody?.Length ?? 0;
                var respLen = e.ResponseBody?.Length ?? 0;
                var respTrunc = NetworkCaptureLimits.IsResponseBodyTruncated(e) == true ? " respTruncCap" : "";
                var respMismatch = NetworkCaptureLimits.IsResponseBodySizeMismatch(e) == true ? " respLenMismatch" : "";
                sb.AppendLine($"  #{e.Id} {e.Method} {status}{err}{timing}{cache}{src} reqLen={reqLen} respLenCaptured={respLen}{respTrunc}{respMismatch} {FmtUrl(e.Url, maxUrlChars)}");
            }
            return Task.FromResult<object>(TextContent(sb.ToString().TrimEnd()));
        }

        var shown = limit > 0 ? list.TakeLast(limit).ToList() : list;
        if (limit > 0 && list.Count > limit)
            sb.AppendLine($"  (showing last {shown.Count} of {list.Count} — use summary=true for all entries compactly, or increase limit)");

        var maxHeadersPerSide = singleEntry ? 64 : 12;
        foreach (var e in shown)
        {
            var status = e.StatusCode > 0 ? e.StatusCode.ToString() : "---";
            var err = e.IsError ? " [ERROR]" : "";
            var timing = e.DurationMs.HasValue ? $" ({e.DurationMs.Value:F0}ms)" : "";
            var cache = e.ServedFromCache ? " cache" : "";
            var src = e.ResponseSource is "network" or "" ? "" : $" [{e.ResponseSource}]";
            sb.AppendLine($"  #{e.Id} {e.Method} {status}{err}{timing}{cache}{src} {FmtUrl(e.Url, maxUrlChars)}");
            if (!string.IsNullOrEmpty(e.MockRuleKey))
                sb.AppendLine($"    mockRuleKey: {e.MockRuleKey}");

            if (e.RequestBody != null)
                sb.AppendLine($"    Request body: {TruncateNetworkBody(e.RequestBody, bodyMaxChars)}");

            if (includeBody)
            {
                if (e.ResponseBody != null)
                    sb.AppendLine($"    Response body: {TruncateNetworkBody(e.ResponseBody, bodyMaxChars)}");
                else if (NetworkCaptureLimits.ShouldCaptureResponseBody(e.ResourceType, e.ContentType))
                    sb.AppendLine("    Response body: (not captured — cache or stream unavailable; POST /api/fetch is a new request)");
                else
                    sb.AppendLine("    Response body: (not captured)");
            }

            if (includeHeaders)
            {
                if (e.RequestHeaders.Count > 0)
                {
                    sb.AppendLine("    Request headers:");
                    foreach (var h in e.RequestHeaders.Take(maxHeadersPerSide))
                        sb.AppendLine($"      {h.Key}: {h.Value}");
                    if (e.RequestHeaders.Count > maxHeadersPerSide)
                        sb.AppendLine($"      ... and {e.RequestHeaders.Count - maxHeadersPerSide} more request headers");
                }
                if (e.ResponseHeaders.Count > 0)
                {
                    sb.AppendLine("    Response headers:");
                    foreach (var h in e.ResponseHeaders.Take(maxHeadersPerSide))
                        sb.AppendLine($"      {h.Key}: {h.Value}");
                    if (e.ResponseHeaders.Count > maxHeadersPerSide)
                        sb.AppendLine($"      ... and {e.ResponseHeaders.Count - maxHeadersPerSide} more response headers");
                }
            }
        }

        return Task.FromResult<object>(TextContent(sb.ToString().TrimEnd()));
        });
    }

private async Task<object> ToolWait(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref' (from browser_snapshot), 'selector' (CSS), or a semantic locator to identify the element to wait for.");

        var timeout = GetInt(args, "timeout", 10000);
        var state = GetString(args, "state") ?? "visible";
        try
        {
            await _context.WaitForElement(selector, timeout, state);
            return TextContent($"Element found ({state}): {Fmt(selector)}");
        }
        catch (TimeoutException)
        {
            return TextContent($"Timeout: element not {state} within {timeout}ms — {Fmt(selector)}");
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolWaitForFinalNavigation(JsonElement args)
    {
        var quietPeriod = GetInt(args, "quietPeriod", 500);
        var timeout = GetInt(args, "timeout", 15000);

        var navCount = await _context.WaitForFinalNavigation(quietPeriod, timeout);
        var url = await _context.GetCurrentUrl();
        var title = await _context.GetTitle();

        if (navCount == 0)
            return TextContent($"No navigations observed within {timeout}ms.\nURL: {url}\nTitle: {title}");

        return TextContent($"Navigation chain settled after {navCount} navigation(s).\nURL: {url}\nTitle: {title}");
    }

private async Task<object> ToolWaitForIdle(JsonElement args)
    {
        var quietPeriod = GetInt(args, "quietPeriod", 500);
        var timeout = GetInt(args, "timeout", 10000);

        var idle = await _context.WaitForIdle(quietPeriod, timeout);
        return idle
            ? TextContent($"Idle (network quiet + no CSS animations) after {quietPeriod}ms quiet window.")
            : TextContent($"Timeout: page did not become idle within {timeout}ms (quietPeriod={quietPeriod}ms).");
    }

private async Task<object> ToolAssertText(JsonElement args)
    {
        var text = GetString(args, "text");
        if (string.IsNullOrEmpty(text))
            return ErrorContent("Missing required field: text");

        var shouldNotContain = GetBool(args, "shouldNotContain");
        var message = GetString(args, "message");

        if (shouldNotContain)
            await _context.AssertPageNotContains(text, message);
        else
            await _context.AssertPageContains(text, message);

        var last = _context.Assert.Results.Last();
        var summary = $"Assertions: {_context.Assert.PassCount} passed, {_context.Assert.FailCount} failed";
        var detail = last.Details != null ? $"\n  {last.Details}" : "";
        return TextContent($"{(last.Passed ? "PASS" : "FAIL")}: {last.Description}{detail}\n{summary}");
    }

private async Task<object> ToolAssertElement(JsonElement args)
    {
        var selector = ResolveElement(args);
        if (selector == null)
            return ErrorContent("Provide 'ref', 'selector', or a semantic locator to identify the element.");

        var message = GetString(args, "message");

        if (args.TryGetProperty("visible", out var visibleProp))
        {
            var shouldBeVisible = visibleProp.ValueKind == JsonValueKind.True;
            if (shouldBeVisible)
                await _context.AssertElementVisible(selector, message);
            else
                await _context.AssertElementNotVisible(selector, message);
        }
        else if (args.TryGetProperty("hasText", out var hasTextProp) && hasTextProp.ValueKind == JsonValueKind.String)
        {
            await _context.AssertElementText(selector, hasTextProp.GetString()!, message);
        }
        else if (args.TryGetProperty("containsText", out var containsProp) && containsProp.ValueKind == JsonValueKind.String)
        {
            await _context.AssertElementContainsText(selector, containsProp.GetString()!, message);
        }
        else if (args.TryGetProperty("attribute", out var attrProp) && attrProp.ValueKind == JsonValueKind.String)
        {
            var expected = GetString(args, "expected");
            if (string.IsNullOrEmpty(expected))
                return ErrorContent("Missing 'expected' value for attribute assertion.");
            await _context.AssertElementAttribute(selector, attrProp.GetString()!, expected, message);
        }
        else if (args.TryGetProperty("count", out var countProp) && countProp.ValueKind == JsonValueKind.Number)
        {
            await _context.AssertElementCount(selector, countProp.GetInt32(), message);
        }
        else
        {
            return ErrorContent("Specify an assertion type: visible, hasText, containsText, attribute+expected, or count.");
        }

        return FormatAssertResult();
    }

private async Task<object> ToolAssertUrl(JsonElement args)
    {
        var expected = GetString(args, "expected");
        if (string.IsNullOrEmpty(expected))
            return ErrorContent("Missing required field: expected");

        var message = GetString(args, "message");
        await _context.AssertUrl(expected, message);
        return FormatAssertResult();
    }

private async Task<object> ToolAssertTitle(JsonElement args)
    {
        var expected = GetString(args, "expected");
        if (string.IsNullOrEmpty(expected))
            return ErrorContent("Missing required field: expected");

        var message = GetString(args, "message");
        await _context.AssertTitle(expected, message);
        return FormatAssertResult();
    }

private object ToolTabs()
    {
        var tabs = _context.GetTabs();
        if (tabs.Count == 0)
            return TextContent("No tabs open.");

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Open tabs ({tabs.Count}):");
        foreach (var t in tabs)
        {
            var marker = t.IsActive ? " [ACTIVE]" : "";
            var title = string.IsNullOrEmpty(t.Title) ? "(untitled)" : t.Title;
            sb.AppendLine($"  [{t.Index}]{marker} ({t.Owner}) {title} — {t.Url}");
        }
        return TextContent(sb.ToString().TrimEnd());
    }

private async Task<object> ToolNewTab(JsonElement args)
    {
        var url = GetString(args, "url");
        var owner = GetString(args, "owner") ?? TabOwners.Agent;

        try
        {
            var tabIndex = await _context.NewTab(url, owner);
            var tabs = _context.GetTabs();
            var tab = tabs.FirstOrDefault(t => t.Index == tabIndex);
            return TextContent($"Opened new tab [{tabIndex}] ({tab?.Owner ?? owner}): {tab?.Title ?? "New Tab"} — {tab?.Url ?? url ?? "(welcome page)"}\nTotal tabs: {_context.GetTabCount()}");
        }
        catch (Exception ex)
        {
            return ErrorContent($"Failed to create tab: {ex.Message}");
        }
    }

private async Task<object> ToolCloseTab(JsonElement args)
    {
        var tabIndex = GetInt(args, "tabIndex", -1);
        if (tabIndex < 0)
            tabIndex = GetInt(args, "index", -1);
        if (tabIndex < 0)
            return ErrorContent("Missing required field: tabIndex");

        try
        {
            await _context.CloseTab(tabIndex);
            return TextContent($"Closed tab [{tabIndex}]. Active tab is now [{_context.GetActiveTabIndex()}]. Total tabs: {_context.GetTabCount()}");
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private object ToolSwitchTab(JsonElement args)
    {
        var tabIndex = GetInt(args, "tabIndex", -1);
        if (tabIndex < 0)
            return ErrorContent("Missing required field: tabIndex");

        try
        {
            _context.SwitchTab(tabIndex);
            var tab = _context.ActiveTab;
            return TextContent($"Switched to tab [{tabIndex}]: {tab.Title} — {tab.Url}");
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

private async Task<object> ToolViewport(JsonElement args)
    {
        var preset = GetString(args, "preset");
        if (!string.IsNullOrEmpty(preset))
        {
            try
            {
                await _context.SetViewport(preset);
            }
            catch (ArgumentException ex)
            {
                return ErrorContent(ex.Message);
            }
            var (w, h) = await _context.GetViewportSize();
            var desc = preset.Equals("Desktop", StringComparison.OrdinalIgnoreCase)
                ? "Desktop (full screen)"
                : $"{preset} ({w}×{h})";
            return TextContent($"Viewport set to {desc}");
        }

        var width = GetInt(args, "width", 0);
        var height = GetInt(args, "height", 0);

        if (width > 0 && height > 0)
        {
            try
            {
                await _context.SetViewport(width, height);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                return ErrorContent(ex.Message);
            }
            var (w, h) = await _context.GetViewportSize();
            return TextContent($"Viewport set to {w}×{h}");
        }

        // No args = return current viewport info
        var (cw, ch) = await _context.GetViewportSize();
        var overridden = _context.ViewportOverride.HasValue;
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Current viewport: {cw}×{ch}{(overridden ? " (overridden)" : " (default)")}");
        sb.AppendLine("Available presets:");
        foreach (var p in AutomationContext.ViewportPresets)
        {
            if (p.Value.Width == 0)
                sb.AppendLine($"  {p.Key} — full screen (reset)");
            else
                sb.AppendLine($"  {p.Key} — {p.Value.Width}×{p.Value.Height}");
        }
        return TextContent(sb.ToString().TrimEnd());
    }

    private async Task<object> ToolEmulation(JsonElement args)
    {
        var action = (GetString(args, "action") ?? "get").ToLowerInvariant();
        try
        {
            if (action is "clear" or "reset")
            {
                await _context.ClearEmulation();
                return TextContent("Emulation overrides cleared.");
            }

            if (action == "set")
            {
                var update = new EmulationUpdate();
                if (args.TryGetProperty("geolocation", out var geo))
                {
                    if (geo.ValueKind == JsonValueKind.Null)
                        update.Geolocation = new GeoUpdate { Clear = true };
                    else if (geo.ValueKind == JsonValueKind.Object)
                    {
                        update.Geolocation = new GeoUpdate
                        {
                            Clear = geo.TryGetProperty("clear", out var c) && c.ValueKind == JsonValueKind.True,
                            Latitude = geo.TryGetProperty("latitude", out var lat) && lat.ValueKind == JsonValueKind.Number
                                ? lat.GetDouble() : null,
                            Longitude = geo.TryGetProperty("longitude", out var lng) && lng.ValueKind == JsonValueKind.Number
                                ? lng.GetDouble() : null,
                            Accuracy = geo.TryGetProperty("accuracy", out var acc) && acc.ValueKind == JsonValueKind.Number
                                ? acc.GetDouble() : null
                        };
                    }
                }

                if (args.TryGetProperty("locale", out _))
                    update.Locale = GetString(args, "locale") ?? "";
                if (args.TryGetProperty("timezone", out _))
                    update.Timezone = GetString(args, "timezone") ?? "";
                if (args.TryGetProperty("colorScheme", out _))
                    update.ColorScheme = GetString(args, "colorScheme");
                if (args.TryGetProperty("reducedMotion", out _))
                    update.ReducedMotion = GetString(args, "reducedMotion");
                if (args.TryGetProperty("userAgent", out _))
                    update.UserAgent = GetString(args, "userAgent") ?? "";
                if (args.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Object)
                {
                    update.Permissions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in perms.EnumerateObject())
                        update.Permissions[p.Name] = p.Value.GetString() ?? "prompt";
                }

                await _context.SetEmulation(update);
            }

            return TextContent(JsonSerializer.Serialize(_context.Emulation.ToApiObject(), CompactJson));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            return ErrorContent(ex.Message);
        }
    }

    private object ToolTrace(JsonElement args)
    {
        var action = (GetString(args, "action") ?? "get").ToLowerInvariant();
        return action switch
        {
            "start" => TextContent(JsonSerializer.Serialize(
                _context.StartTrace(GetBool(args, "domSnapshots"), GetInt(args, "maxSteps", 200)), CompactJson)),
            "stop" => TextContent(JsonSerializer.Serialize(_context.StopTrace(), CompactJson)),
            "export" => TextContent(JsonSerializer.Serialize(_context.ExportTrace(), CompactJson)),
            _ => TextContent(JsonSerializer.Serialize(_context.GetTrace(), CompactJson))
        };
    }

private async Task<object> ToolWebMcpTools()
    {
        var tools = await _context.GetWebMcpTools();
        if (tools.Count == 0)
            return TextContent("No WebMCP tools detected on this page. " +
                "Pages can register tools via navigator.modelContext.registerTool() " +
                "to expose structured actions to AI agents.");

        var json = JsonSerializer.Serialize(tools, CompactJson);
        return TextContent($"WebMCP tools detected ({tools.Count}):\n{json}");
    }

private async Task<object> ToolWebMcpCall(JsonElement args)
    {
        var toolName = GetString(args, "tool");
        if (string.IsNullOrEmpty(toolName))
            return ErrorContent("Missing required field: tool");

        string? argsJson = null;
        if (args.TryGetProperty("arguments", out var argsProp) && argsProp.ValueKind == JsonValueKind.Object)
            argsJson = argsProp.GetRawText();

        var result = await _context.CallWebMcpTool(toolName, argsJson);
        var json = JsonSerializer.Serialize(result, CompactJson);

        if (result.ContainsKey("error"))
            return ErrorContent(result["error"]?.ToString() ?? "Unknown error");

        return TextContent($"WebMCP tool \"{toolName}\" result:\n{json}");
    }

private async Task<object> ToolHandleDialog(JsonElement args)
    {
        var accept = GetBool(args, "accept") || !args.TryGetProperty("accept", out _);
        var promptText = GetString(args, "promptText");

        _context.SetDialogHandling(accept, promptText);
        await _context.TryApplyDialogConfigAsync();

        var desc = accept ? "accept" : "dismiss";
        var prompt = promptText != null ? $" with text \"{promptText}\"" : "";
        return TextContent($"Dialogs will be {desc}d{prompt}. This applies to the next dialog that appears.");
    }

private Task<object> ToolGetDialog()
    {
        var dialog = _context.GetDialogSnapshot();
        if (dialog == null)
            return Task.FromResult<object>(TextContent("No dialog has appeared."));

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Dialog type: {dialog.Type}");
        sb.AppendLine($"Message: {dialog.Message}");
        if (dialog.DefaultValue != null)
            sb.AppendLine($"Default value: {dialog.DefaultValue}");
        return Task.FromResult<object>(TextContent(sb.ToString().TrimEnd()));
    }

private async Task<object> ToolRunScript(JsonElement args)
    {
        if (_scriptEngine == null)
            return ErrorContent("Script engine not available.");

        var code = GetString(args, "code");
        if (string.IsNullOrWhiteSpace(code))
            return ErrorContent("Missing required field: code");

        _context.Assert.Reset();
        _context.Laws?.BeginScriptLawSession();
        _context.BeginScriptLogCapture();
        ScriptResult result;
        try
        {
            result = await _scriptEngine.ExecuteAsync(code);
        }
        finally
        {
            _context.Laws?.EndScriptLawSession();
        }

        var logLines = _context.ConsumeScriptLogCapture();
        var sb = new System.Text.StringBuilder();

        if (logLines.Count > 0)
        {
            foreach (var line in logLines)
                sb.AppendLine(line);
            sb.AppendLine();
        }

        if (result.Success)
        {
            if (_context.Assert.TotalCount > 0)
            {
                sb.AppendLine($"PASSED: {_context.Assert.PassCount}  FAILED: {_context.Assert.FailCount}  TOTAL: {_context.Assert.TotalCount}");
                if (!_context.Assert.AllPassed)
                {
                    sb.AppendLine();
                    sb.AppendLine("Failed assertions:");
                    foreach (var r in _context.Assert.Results.Where(r => !r.Passed))
                        sb.AppendLine($"  - {r.Description}{(r.Details != null ? $": {r.Details}" : "")}");
                }
            }
            else
            {
                sb.AppendLine("Script completed successfully (no assertions).");
            }

            if (result.ReturnValue != null)
                sb.AppendLine($"Return value: {result.ReturnValue}");

            sb.AppendLine($"Elapsed: {result.ElapsedMs}ms");
        }
        else
        {
            sb.AppendLine($"SCRIPT ERROR: {result.Error}");
            if (_context.Assert.TotalCount > 0)
                sb.AppendLine($"Assertions before error: PASSED: {_context.Assert.PassCount}  FAILED: {_context.Assert.FailCount}");
            sb.AppendLine($"Elapsed: {result.ElapsedMs}ms");
        }


        return TextContent(sb.ToString().TrimEnd());
    }

    private async Task<object> ToolFetchRaw(JsonElement args)
    {
        var url = GetString(args, "url");
        if (string.IsNullOrWhiteSpace(url))
            return ErrorContent("Missing required field: url");

        var json = await _context.FetchRaw(
            url,
            requestLine: GetString(args, "requestLine"),
            headers: GetString(args, "headers"),
            body: GetString(args, "body"),
            method: GetString(args, "method"),
            timeoutMs: GetInt(args, "timeout", 15000),
            normalizeHeaders: GetOptOutBool(args, "normalizeHeaders"));
        return TextContent(json);
    }

    private Task<object> ToolHeaderOverrides(JsonElement args)
    {
        var action = (GetString(args, "action") ?? "get").Trim().ToLowerInvariant();
        if (action is "set" or "replace")
        {
            var items = new List<HeaderOverride>();
            if (args.TryGetProperty("headers", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                {
                    if (el.ValueKind != JsonValueKind.Object) continue;
                    var name = GetString(el, "name");
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    items.Add(new HeaderOverride
                    {
                        Name = name.Trim(),
                        Value = GetString(el, "value") ?? "",
                        Enabled = !el.TryGetProperty("enabled", out var en) || en.ValueKind != JsonValueKind.False
                    });
                }
            }
            _context.SetHeaderOverrides(items);
        }
        else if (action == "clear")
        {
            _context.ClearHeaderOverrides();
        }

        var all = _context.GetHeaderOverrides();
        return Task.FromResult(TextContent(JsonSerializer.Serialize(new
        {
            count = all.Count,
            enabledCount = all.Count(h => h.Enabled),
            headers = all.Select(h => new { name = h.Name, value = h.Value, enabled = h.Enabled })
        })));
    }

    private Task<object> ToolRecordStart(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRecordStartAsync);

    private Task<object> ToolRecordStatus(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRecordStatusAsync);

    private Task<object> ToolRecordStop(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildRecordStopAsync);

    private async Task<object> ToolSseConnections(JsonElement args)
    {
        int? tabIdx = null;
        if (args.TryGetProperty("tabIndex", out var ti) && ti.TryGetInt32(out var idx) && idx >= 0)
            tabIdx = idx;

        return await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
            await _context.RefreshOpenSseCaptureFromCdpAsync();
            var mgr = _context.ActiveTab.Sse;
            var url = GetString(args, "url");
            var state = GetString(args, "state");
            var list = mgr.GetConnections(stateFilter: state, urlFilter: url);
            return (object)TextContent(JsonSerializer.Serialize(new
            {
                connections = list.Select(c => new
                {
                    c.ConnectionId,
                    c.Url,
                    c.Method,
                    c.State,
                    c.MessagesReceived,
                    c.LastEventIdSent
                }),
                count = list.Count
            }, CompactJson));
        });
    }

    private async Task<object> ToolSseMessages(JsonElement args)
    {
        int? tabIdx = null;
        if (args.TryGetProperty("tabIndex", out var ti) && ti.TryGetInt32(out var idx) && idx >= 0)
            tabIdx = idx;

        return await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
            await _context.RefreshOpenSseCaptureFromCdpAsync();
            var mgr = _context.ActiveTab.Sse;
            var connId = GetInt(args, "connectionId", 0);
            var eventFilter = GetString(args, "event");
            var limit = GetInt(args, "limit", 100);
            var messages = connId > 0
                ? mgr.GetMessages(connId, eventNameFilter: eventFilter, last: limit)
                : mgr.GetConnections()
                    .SelectMany(c => mgr.GetMessages(c.ConnectionId, eventNameFilter: eventFilter, last: limit))
                    .Take(limit)
                    .ToList();
            return (object)TextContent(JsonSerializer.Serialize(new
            {
                messages = messages.Select(m => new
                {
                    m.MessageId,
                    m.ConnectionId,
                    m.EventName,
                    m.EventId,
                    data = m.Data.Length > 2000 ? m.Data[..2000] + "..." : m.Data,
                    m.Timestamp
                }),
                count = messages.Count
            }, CompactJson));
        });
    }
}
