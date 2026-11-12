using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Recording;

/// <summary>
/// Records user interactions in the browser and writes them as a .csx test script
/// using Trowser's scripting API. Actions are flushed to disk immediately so the
/// file is always up-to-date while recording.
/// <para>
/// Capture JS is shared with Mirror Mode and the session journal. Which action
/// types this recorder writes is decided by <see cref="CapturedActionRouting"/>
/// (scroll is live-only, not recorded).
/// </para>
/// </summary>
public class ScriptRecorder
{
    private StreamWriter? _writer;
    private StreamWriter? _narrationWriter;
    private string? _filePath;
    private string? _narrationPath;
    private string? _lastUrl;
    private string? _startUrl;
    private DateTime _startedAt;
    private int _actionCount;
    private bool _expectingNavigation;
    private bool _wroteWaitAfterClick;
    private DateTime _lastActionTime = DateTime.UtcNow;
    private readonly HashSet<string> _usedVariables = new(StringComparer.Ordinal);

    public bool IsRecording => _writer != null;
    public string? FilePath => _filePath;
    public string? StartUrl => _startUrl;
    public DateTime? StartedAt => _writer != null ? _startedAt : null;
    public int ActionCount => _actionCount;

    /// <summary>Create a crash-safe temp .csx path under %TEMP%\Trowser\recordings\.</summary>
    public static string CreateTempCsxPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Trowser", "recordings");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"recording-{DateTime.Now:yyyyMMdd-HHmmss}.csx");
    }

    /// <summary>Start recording to a temp .csx (and parallel narration file).</summary>
    public void StartTemp(string currentUrl) => Start(CreateTempCsxPath(), currentUrl);

    public void Start(string filePath, string currentUrl)
    {
        // Discard any in-progress recording without returning a result (replaced by a new start).
        if (_writer != null)
            _ = Stop();

        _filePath = filePath;
        _startUrl = currentUrl;
        _lastUrl = currentUrl;
        _startedAt = DateTime.Now;
        _actionCount = 0;
        _expectingNavigation = false;
        _lastActionTime = DateTime.UtcNow;
        _usedVariables.Clear();

        _writer = new StreamWriter(filePath, false, new UTF8Encoding(false)) { AutoFlush = true };

        _writer.WriteLine($"// Recorded by Trowser on {_startedAt:yyyy-MM-dd HH:mm:ss}");
        _writer.WriteLine($"// Start URL: {Sanitize(currentUrl)}");
        _writer.WriteLine();

        // Parallel human-readable narration next to the .csx (e.g. login_text.md).
        // Best-effort: a narration failure must never break script recording.
        try
        {
            var dir = Path.GetDirectoryName(filePath);
            var baseName = Path.GetFileNameWithoutExtension(filePath);
            _narrationPath = Path.Combine(dir ?? "", baseName + "_text.md");
            _narrationWriter = new StreamWriter(_narrationPath, false, new UTF8Encoding(false)) { AutoFlush = true };
            _narrationWriter.WriteLine($"# Recorded steps — {_startedAt:yyyy-MM-dd HH:mm:ss}");
            _narrationWriter.WriteLine();
            _narrationWriter.WriteLine($"Start: {currentUrl}");
            _narrationWriter.WriteLine();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Recorder narration file failed: {ex.Message}");
            _narrationWriter = null;
            _narrationPath = null;
        }
    }

    /// <summary>Absolute path of the parallel narration file, or null when not recording.</summary>
    public string? NarrationPath => _narrationPath;

    /// <summary>Write one human-readable narration line to the parallel .steps.md file (best-effort).</summary>
    private void Narrate(string? line)
    {
        if (_narrationWriter == null || string.IsNullOrEmpty(line)) return;
        try { _narrationWriter.WriteLine($"- {line}"); }
        catch (Exception ex) { TrowserLog.Warn($"Recorder narration write failed: {ex.Message}"); }
    }

    /// <summary>
    /// Stop recording, close writers, and return a snapshot. Temp files remain on disk until
    /// <see cref="RecordingStopResult.DeleteTempFiles"/> is called. Returns null if not recording.
    /// </summary>
    public RecordingStopResult? Stop()
    {
        if (_writer == null) return null;

        var csxPath = _filePath;
        var narrationPath = _narrationPath;
        var startUrl = _startUrl ?? "";
        var startedAt = _startedAt;
        var actionCount = _actionCount;

        try
        {
            _writer.WriteLine();
            _writer.WriteLine("// Recording stopped");
            _writer.Flush();
            _writer.Dispose();
        }
        catch (Exception ex) { TrowserLog.Warn($"Recorder stop failed: {ex.Message}"); }

        try
        {
            if (_narrationWriter != null)
            {
                _narrationWriter.WriteLine();
                _narrationWriter.WriteLine("_Recording stopped._");
                _narrationWriter.Flush();
                _narrationWriter.Dispose();
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"Recorder narration stop failed: {ex.Message}"); }

        _writer = null;
        _narrationWriter = null;
        _filePath = null;
        _narrationPath = null;
        _startUrl = null;
        _actionCount = 0;

        var script = "";
        var narration = "";
        try
        {
            if (!string.IsNullOrEmpty(csxPath) && File.Exists(csxPath))
                script = File.ReadAllText(csxPath, new UTF8Encoding(false));
        }
        catch (Exception ex) { TrowserLog.Warn($"Recorder read script failed: {ex.Message}"); }

        try
        {
            if (!string.IsNullOrEmpty(narrationPath) && File.Exists(narrationPath))
                narration = File.ReadAllText(narrationPath, new UTF8Encoding(false));
        }
        catch (Exception ex) { TrowserLog.Warn($"Recorder read narration failed: {ex.Message}"); }

        return new RecordingStopResult
        {
            Script = script,
            Narration = narration,
            StartUrl = startUrl,
            StartedAt = startedAt,
            ActionCount = actionCount,
            TempCsxPath = csxPath,
            TempNarrationPath = narrationPath
        };
    }

    /// <summary>
    /// Called when a navigation completes that was triggered by a click, redirect,
    /// or other non-address-bar cause. Never writes Navigate() -- only WaitForElement
    /// after the first navigation following a recorded click, then silently absorbs
    /// any redirect chain navigations.
    /// </summary>
    public void RecordNavigation(string url)
    {
        if (_writer == null) return;
        if (url == _lastUrl) return;
        if (url.StartsWith("data:")) return;

        _lastUrl = url;

        if (_expectingNavigation && !_wroteWaitAfterClick)
        {
            _wroteWaitAfterClick = true;
            WriteLine($"await WaitForElement(\"body\", 5000);");
            WriteLine();
            Narrate(ActionNarrator.DescribeNavigation(url));
            _actionCount++;
        }
        // Otherwise: redirect in a chain or unexpected navigation -- silently track URL
    }

    /// <summary>
    /// Called only when the user navigates via the address bar. This is the only
    /// case where we write a Navigate() call in the recorded script.
    /// </summary>
    public void RecordAddressBarNavigation(string url)
    {
        if (_writer == null) return;
        if (url.StartsWith("data:")) return;

        _expectingNavigation = false;
        _wroteWaitAfterClick = false;
        _lastUrl = url;

        WriteLine();
        WriteLine($"await Navigate({Escape(url)});");
        WriteLine("await WaitForElement(\"body\", 15000);");
        WriteLine();
        Narrate(ActionNarrator.DescribeNavigation(url));
        _actionCount++;
    }

    /// <summary>
    /// Process a recorded action from the injected JavaScript.
    /// </summary>
    public void RecordAction(JsonElement action)
    {
        if (_writer == null) return;

        var type = action.GetProperty("type").GetString();
        if (!CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Script, type))
            return;

        // A new user action means any prior click->navigation chain is over
        if (type != "click" && type != "hover")
        {
            _expectingNavigation = false;
            _wroteWaitAfterClick = false;
        }

        switch (type)
        {
            case "click":
                RecordClick(action);
                break;
            case "hover":
                RecordHover(action);
                break;
            case "radio":
                RecordRadio(action);
                break;
            case "type":
                RecordType(action);
                break;
            case "select":
                RecordSelect(action);
                break;
            case "key":
                RecordKey(action);
                break;
            case "scroll":
                RecordScroll(action);
                break;
            case "assert":
                RecordAssert(action);
                break;
            case "elementOfInterest":
                RecordElementOfInterest(action);
                break;
            default:
                WriteLine($"// Unknown recorded action: {Sanitize(type)}");
                break;
        }

        Narrate(ActionNarrator.Describe(action));

        _actionCount++;
        _lastActionTime = DateTime.UtcNow;
    }

    /// <summary>
    /// Record a comment noting a tab switch.
    /// </summary>
    public void RecordTabSwitch(int tabIndex, string title)
    {
        if (_writer == null) return;
        WriteLine();
        WriteLine($"// Switched to tab {tabIndex}: {Sanitize(title)}");
        _actionCount++;
    }

    /// <summary>
    /// Append a script block that was executed from the script console.
    /// Variable names that collide with earlier declarations are automatically
    /// suffixed with a counter (e.g. url → url2 → url3) so the combined .csx compiles.
    /// </summary>
    public void RecordScriptBlock(string code)
    {
        if (_writer == null) return;
        if (string.IsNullOrWhiteSpace(code)) return;

        var modifiedCode = DeduplicateVariables(code);

        WriteLine();
        WriteLine("// --- Script executed from console ---");
        foreach (var line in modifiedCode.Split('\n'))
            WriteLine(line.TrimEnd('\r'));
        WriteLine("// --- End of console script ---");
        WriteLine();
        _actionCount++;
    }

    private static readonly Regex VarDeclPattern = new(
        @"(?:^|(?<=[\s;{]))\s*(?:var|string|int|bool|double|float|long|decimal|char|byte|short|uint|ulong|ushort|sbyte|object|dynamic|[A-Z]\w*(?:<[^>]*>)?(?:\[\])?(?:\?)?)\s+(\w+)\s*[=;]",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private string DeduplicateVariables(string code)
    {
        var matches = VarDeclPattern.Matches(code);
        if (matches.Count == 0) return code;

        var renames = new Dictionary<string, string>();

        foreach (Match match in matches)
        {
            var varName = match.Groups[1].Value;

            if (renames.ContainsKey(varName))
                continue;

            if (_usedVariables.Contains(varName))
            {
                var counter = 2;
                string newName;
                do
                {
                    newName = $"{varName}{counter}";
                    counter++;
                } while (_usedVariables.Contains(newName) || renames.ContainsValue(newName));

                renames[varName] = newName;
                _usedVariables.Add(newName);
            }
            else
            {
                _usedVariables.Add(varName);
            }
        }

        if (renames.Count == 0) return code;

        // Replace longest names first to avoid partial matches (e.g. "url" replacing inside "urlPath")
        foreach (var (oldName, newName) in renames.OrderByDescending(r => r.Key.Length))
        {
            code = Regex.Replace(code, $@"\b{Regex.Escape(oldName)}\b", newName);
        }

        return code;
    }

    private void RecordClick(JsonElement action)
    {
        var tag = GetString(action, "tag");
        var href = GetString(action, "href");
        var locator = BuildLocator(action, isClickable: true);

        // Any click might cause navigation (links, buttons, form submits, JS handlers).
        // Set the flag so subsequent NavigationCompleted events produce WaitForElement
        // instead of Navigate(), and redirect chains are absorbed silently.
        _expectingNavigation = true;
        _wroteWaitAfterClick = false;

        WriteLine($"await Click({locator});");
    }

    private void RecordHover(JsonElement action)
    {
        var locator = BuildLocator(action, isClickable: true);
        WriteLine($"await Hover({locator});");
    }

    private void RecordAssert(JsonElement action)
    {
        var text = Sanitize(GetString(action, "text"));
        if (string.IsNullOrEmpty(text)) return;

        if (text.Length <= 80)
        {
            WriteLine($"await AssertPageContains({Escape(text)});");
        }
        else
        {
            var snippet = text[..60].TrimEnd();
            WriteLine($"await AssertPageContains({Escape(snippet)});");
        }
    }

    private void RecordElementOfInterest(JsonElement action)
    {
        var tag = GetString(action, "tag");
        var text = Sanitize(GetString(action, "text"));
        var role = GetString(action, "role");
        var label = Sanitize(GetString(action, "label"));
        var inputType = GetString(action, "inputType");
        var href = GetString(action, "href");

        var desc = new System.Text.StringBuilder();

        if (!string.IsNullOrEmpty(role))
            desc.Append(role);
        else if (tag == "input" && !string.IsNullOrEmpty(inputType))
            desc.Append($"{inputType} input");
        else
            desc.Append(tag);

        var name = !string.IsNullOrEmpty(label) ? label
                 : !string.IsNullOrEmpty(text) ? text : "";
        if (name.Length > 60) name = name[..57] + "...";
        if (!string.IsNullOrEmpty(name))
            desc.Append($" \"{name}\"");

        if (!string.IsNullOrEmpty(href))
        {
            var shortHref = href.Length <= 50 ? href : href[..47] + "...";
            desc.Append($" → {shortHref}");
        }

        WriteLine($"// Element of interest: {Sanitize(desc.ToString())}");
    }

    /// <summary>
    /// Flatten page-supplied text to one line. Every value that ends up inside a <c>//</c> comment
    /// must pass through here: C# ends a comment at CR, LF, U+0085, U+2028 and U+2029, so a page
    /// that smuggles any of them into a label could otherwise inject code into the recorded .csx.
    /// </summary>
    internal static string Sanitize(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(char.IsControl(c) || c is '\u0085' or '\u2028' or '\u2029' ? ' ' : c);
        return Regex.Replace(sb.ToString(), @"\s{2,}", " ").Trim();
    }

    private void RecordRadio(JsonElement action)
    {
        var radioIndex = action.TryGetProperty("radioIndex", out var idx) ? idx.GetInt32() : -1;
        var radioValue = Sanitize(GetString(action, "radioValue"));
        var groupLabel = Sanitize(GetString(action, "groupLabel"));

        if (!string.IsNullOrEmpty(groupLabel))
            WriteLine($"// {groupLabel} \u2192 {radioValue}");

        if (radioIndex >= 0)
        {
            WriteLine($"await ExecuteJs(\"document.querySelectorAll('input[type=radio]')[{radioIndex}].click()\");");
        }
        else
        {
            WriteLine($"// Radio button clicked: {radioValue} (could not determine index)");
        }
    }

    private void RecordType(JsonElement action)
    {
        var locator = BuildLocator(action, isClickable: false);
        var value = GetString(action, "value");
        var inputType = GetString(action, "inputType").ToLowerInvariant();

        if (inputType == "password")
        {
            WriteLine($"await Type({locator}, \"***\"); // TODO: Replace with actual password");
        }
        else
        {
            WriteLine($"await Type({locator}, {Escape(value)});");
        }
    }

    private void RecordSelect(JsonElement action)
    {
        var locator = BuildLocator(action, isClickable: false);
        var value = GetString(action, "value");
        var selectedText = Sanitize(GetString(action, "selectedText"));

        var comment = string.IsNullOrEmpty(selectedText) ? "" : $" // \"{selectedText}\"";
        WriteLine($"await Select({locator}, {Escape(value)});{comment}");
    }

    /// <summary>
    /// How a scroll would be written if <see cref="CapturedActionRouting"/> ever
    /// enables <see cref="CapturedActionRouting.Sink.Script"/> for <c>scroll</c>.
    /// Currently Mirror-only — see the catalog row for why.
    /// </summary>
    private void RecordScroll(JsonElement action)
    {
        var x = GetNumber(action, "scrollX");
        var y = GetNumber(action, "scrollY");
        var selector = GetString(action, "selector");
        var xv = x.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var yv = y.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (!string.IsNullOrEmpty(selector))
            WriteLine($"await Scroll({Escape(selector)}, x: {xv}, y: {yv});");
        else
            WriteLine($"await Scroll(x: {xv}, y: {yv});");
    }

    private void RecordKey(JsonElement action)
    {
        var key = GetString(action, "key");
        if (string.IsNullOrEmpty(key)) return;

        var ctrl = GetBool(action, "ctrlKey");
        var alt = GetBool(action, "altKey");
        var shift = GetBool(action, "shiftKey");
        var meta = GetBool(action, "metaKey");

        var modifiers = new List<string>();
        if (ctrl) modifiers.Add("\"Control\"");
        if (alt) modifiers.Add("\"Alt\"");
        if (shift) modifiers.Add("\"Shift\"");
        if (meta) modifiers.Add("\"Meta\"");

        if (modifiers.Count > 0)
        {
            var modArray = $"new[] {{ {string.Join(", ", modifiers)} }}";
            WriteLine($"await PressKey({Escape(key)}, modifiers: {modArray});");
        }
        else
        {
            WriteLine($"await PressKey({Escape(key)});");
        }
    }

    /// <summary>
    /// Build the best locator expression for a recorded element, using semantic
    /// locators when possible and falling back to CSS selectors.
    /// </summary>
    private static string BuildLocator(JsonElement action, bool isClickable) =>
        LocatorBuilder.ToScriptExpression(LocatorBuilder.ChooseFromJson(action, isClickable), Escape);

    private void WriteLine(string line = "")
    {
        try { _writer?.WriteLine(line); }
        catch (Exception ex) { TrowserLog.Warn($"Recorder write failed: {ex.Message}"); }
    }

    /// <summary>Render <paramref name="value"/> as a C# regular string literal, safe for any input.</summary>
    internal static string Escape(string value)
    {
        var sb = new StringBuilder(value.Length + 2);
        sb.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (char.IsControl(c) || c is '\u0085' or '\u2028' or '\u2029')
                        sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else
                        sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static string GetString(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.String)
            return val.GetString() ?? "";
        return "";
    }

    private static bool GetBool(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.True)
            return true;
        return false;
    }

    private static double GetNumber(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var val)) return 0;
        if (val.ValueKind == JsonValueKind.Number) return val.GetDouble();
        if (val.ValueKind == JsonValueKind.String
            && double.TryParse(val.GetString(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed))
            return parsed;
        return 0;
    }

    private static bool IsDifferentOrigin(string? url1, string? url2)
    {
        try
        {
            if (url1 == null || url2 == null) return true;
            var u1 = new Uri(url1);
            var u2 = new Uri(url2);
            return u1.Host != u2.Host;
        }
        catch (Exception ex) { TrowserLog.Warn($"URL origin comparison failed: {ex.Message}"); return true; }
    }

    /// <summary>
    /// Per-process secret that capture messages must carry. The capture script is injected after
    /// page load, so a hostile page that hooks <c>postMessage</c> first can still learn it; this only
    /// stops casual forgery. Never trust recorded fields beyond <see cref="Sanitize"/>/<see cref="Escape"/>.
    /// </summary>
    public static readonly string RecordToken =
        Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

    /// <summary><see cref="InjectionScriptTemplate"/> with <see cref="RecordToken"/> filled in.</summary>
    public static string InjectionScript { get; } =
        InjectionScriptTemplate.Replace("__TROWSER_RECORD_TOKEN__", RecordToken, StringComparison.Ordinal);

    /// <summary>
    /// JavaScript to inject into pages for capturing user interactions.
    /// Posts events via window.chrome.webview.postMessage with type "__trowser_record".
    /// Must be re-injected after each navigation.
    /// </summary>
    private const string InjectionScriptTemplate = """
        (function() {
            if (window.__trowserRecorderHooked) return;
            window.__trowserRecorderHooked = true;

            function collectShadowRoots(root) {
                var roots = [];
                var all = root.querySelectorAll('*');
                for (var i = 0; i < all.length; i++) {
                    if (all[i].shadowRoot) {
                        roots.push(all[i].shadowRoot);
                        roots = roots.concat(collectShadowRoots(all[i].shadowRoot));
                    }
                }
                return roots;
            }

            function isDynamicId(id) {
                if (/^ids-[a-z0-9]+-[a-z0-9]+$/i.test(id)) return true;
                if (/[0-9a-f]{8}-[0-9a-f]{4}-/i.test(id)) return true;
                return false;
            }

            function getLocalSelector(el, root) {
                if (el.id && !isDynamicId(el.id)) {
                    try {
                        var escaped = CSS.escape(el.id);
                        if (root.querySelectorAll('#' + escaped).length === 1)
                            return '#' + escaped;
                    } catch(e) {}
                }
                var testId = el.getAttribute('data-testid');
                if (testId) {
                    var sel = '[data-testid="' + testId.replace(/"/g, '\\"') + '"]';
                    try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                }
                if (el.name && !isDynamicId(el.name)) {
                    var sel = '[name="' + el.name.replace(/"/g, '\\"') + '"]';
                    try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                }
                // Try tag name alone -- works for semantic HTML (article, main, nav, etc.)
                var tagOnly = el.tagName.toLowerCase();
                try { if (root.querySelectorAll(tagOnly).length === 1) return tagOnly; } catch(e) {}

                var parts = [];
                var cur = el;
                while (cur && cur !== root && cur.nodeType === 1 && parts.length < 10) {
                    if (cur.id && !isDynamicId(cur.id)) {
                        parts.unshift('#' + CSS.escape(cur.id));
                        break;
                    }
                    var tag = cur.tagName.toLowerCase();
                    var parent = cur.parentElement;
                    if (parent) {
                        var siblings = Array.from(parent.children).filter(function(c) {
                            return c.tagName === cur.tagName;
                        });
                        if (siblings.length > 1) {
                            var visCount = siblings.filter(function(s) { return !s.hasAttribute('hidden'); }).length;
                            if (visCount === 1 && !cur.hasAttribute('hidden')) {
                                tag += ':not([hidden])';
                            } else {
                                tag += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
                            }
                        }
                    }
                    parts.unshift(tag);
                    cur = cur.parentElement;
                }
                // If path doesn't start from a unique anchor, search further up
                // and connect with descendant combinator for a stable selector
                if (parts.length > 0 && !parts[0].startsWith('#')) {
                    var anchor = cur;
                    while (anchor && anchor !== root && anchor.nodeType === 1) {
                        if (anchor.id && !isDynamicId(anchor.id)) {
                            return '#' + CSS.escape(anchor.id) + ' ' + parts.join(' > ');
                        }
                        var at = anchor.tagName.toLowerCase();
                        try {
                            if (root.querySelectorAll(at).length === 1) {
                                return at + ' ' + parts.join(' > ');
                            }
                        } catch(e) {}
                        anchor = anchor.parentElement;
                    }
                }
                return parts.join(' > ');
            }

            function getSelector(el) {
                var root = el.getRootNode();
                if (root instanceof ShadowRoot) {
                    var innerSel = getLocalSelector(el, root);
                    var hostSel = getSelector(root.host);
                    return hostSel + ' >>> ' + innerSel;
                }
                return getLocalSelector(el, document);
            }

            function getLabel(el) {
                var aria = el.getAttribute('aria-label');
                if (aria) return aria.trim().substring(0, 200);

                var labelledBy = el.getAttribute('aria-labelledby');
                if (labelledBy) {
                    var r = el.getRootNode();
                    var qr = (r instanceof ShadowRoot) ? r : document;
                    var lbl = qr.getElementById ? qr.getElementById(labelledBy) : null;
                    if (lbl) return (lbl.innerText || '').trim().substring(0, 200);
                }

                if (el.id) {
                    var r = el.getRootNode();
                    var qr = (r instanceof ShadowRoot) ? r : document;
                    var lbl = qr.querySelector('label[for="' + el.id + '"]');
                    if (lbl) return (lbl.innerText || '').trim().substring(0, 200);
                }

                var labelAttr = el.getAttribute('label');
                if (labelAttr) return labelAttr.trim().substring(0, 200);

                if (el.title) return el.title.trim().substring(0, 200);

                // For buttons/links, the accessible name comes from text content.
                // Clone and strip decorative elements (icons, SVGs, images, sr-only
                // text) so their alt text doesn't pollute the label.
                var tag = el.tagName.toLowerCase();
                var role = el.getAttribute('role') || '';
                if (tag === 'button' || tag === 'a' || tag === 'summary' ||
                    role === 'button' || role === 'link' || role === 'tab' || role === 'menuitem') {
                    var clone = el.cloneNode(true);
                    var strip = clone.querySelectorAll(
                        'svg, img, [class*="icon"], [class*="Icon"], .sr-only, .visually-hidden, [aria-hidden="true"]');
                    for (var ri = 0; ri < strip.length; ri++) strip[ri].remove();
                    var ct = (clone.textContent || '').trim().replace(/\s+/g, ' ');
                    if (ct && ct.length <= 200) return ct;
                }

                return '';
            }

            function getVisibleText(el) {
                var text = (el.innerText || el.textContent || '').trim();
                if (text.length > 100) text = text.substring(0, 100);
                return text;
            }

            function getRole(el) {
                var role = el.getAttribute('role');
                if (role) return role;
                var tag = el.tagName.toLowerCase();
                if (tag === 'button' || el.type === 'button' || el.type === 'submit' || el.type === 'reset') return 'button';
                if (tag === 'a' && el.href) return 'link';
                if (tag === 'input') {
                    if (el.type === 'checkbox') return 'checkbox';
                    if (el.type === 'radio') return 'radio';
                    return 'textbox';
                }
                if (tag === 'textarea') return 'textbox';
                if (tag === 'select') return 'combobox';
                return '';
            }

            function isElVis(el) {
                if (el.offsetParent === null && el !== document.body) {
                    try {
                        var pos = window.getComputedStyle(el).position;
                        if (pos !== 'fixed' && pos !== 'sticky') return false;
                    } catch(e) { return false; }
                }
                if (el.offsetWidth === 0 && el.offsetHeight === 0) return false;
                return true;
            }
            function isTextUnique(text, tag) {
                if (!text || text.length > 80) return false;
                var count = 0;
                var els = document.querySelectorAll(tag || '*');
                for (var i = 0; i < els.length && count < 2; i++) {
                    var t = (els[i].innerText || els[i].textContent || '').trim();
                    if (t === text) {
                        if (!isElVis(els[i])) continue;
                        count++;
                    }
                }
                return count === 1;
            }

            var recordToken = '__TROWSER_RECORD_TOKEN__';
            var webviewPost = null;
            try { webviewPost = window.chrome.webview.postMessage.bind(window.chrome.webview); } catch(e) {}

            function postAction(data) {
                try {
                    webviewPost({
                        type: '__trowser_record',
                        token: recordToken,
                        action: data
                    });
                } catch(e) {}
            }

            // --- Radio group legend helper ---
            function getRadioGroupLabel(radio) {
                var group = radio.closest('ids-radio-group') || radio.closest('fieldset') || radio.closest('[role=radiogroup]');
                if (!group) return '';
                // Check shadow DOM legend first (IDS components)
                if (group.shadowRoot) {
                    var leg = group.shadowRoot.querySelector('legend');
                    if (leg) return (leg.innerText || '').trim().substring(0, 200);
                }
                // Light DOM legend
                var leg = group.querySelector('legend');
                if (leg) return (leg.innerText || '').trim().substring(0, 200);
                // Fallback: label attribute or aria-label
                return (group.getAttribute('label') || group.getAttribute('aria-label') || '').trim().substring(0, 200);
            }

            function getRadioIndex(radio) {
                var allRadios = document.querySelectorAll('input[type=radio]');
                for (var i = 0; i < allRadios.length; i++) {
                    if (allRadios[i] === radio) return i;
                }
                return -1;
            }

            function isInteractiveTag(node) {
                var t = node.tagName.toLowerCase();
                if (t === 'a' || t === 'button' || t === 'input' ||
                    t === 'select' || t === 'textarea' || t === 'summary') return true;
                var r = node.getAttribute('role');
                if (r === 'button' || r === 'link' || r === 'tab' ||
                    r === 'menuitem' || r === 'checkbox' || r === 'switch') return true;
                return false;
            }

            function findDropdownTrigger(el) {
                var cur = el;
                for (var i = 0; i < 10 && cur; i++) {
                    if (cur.classList) {
                        if (cur.classList.contains('dropdown-menu') ||
                            cur.getAttribute('role') === 'menu' ||
                            cur.getAttribute('role') === 'listbox') {
                            var parent = cur.parentElement;
                            if (parent) {
                                var trigger = parent.querySelector(
                                    '[data-bs-toggle="dropdown"], [data-toggle="dropdown"], .dropdown-toggle, [aria-haspopup]');
                                if (trigger && trigger !== cur) return trigger;
                            }
                            var prev = cur.previousElementSibling;
                            if (prev) return prev;
                        }
                    }
                    var labelledBy = cur.getAttribute && cur.getAttribute('aria-labelledby');
                    if (labelledBy) {
                        var ref = document.getElementById(labelledBy);
                        if (ref && ref !== cur) return ref;
                    }
                    cur = cur.parentElement;
                }
                return null;
            }

            // --- Click capture ---
            document.addEventListener('click', function(e) {
                // Use composedPath to see through shadow DOM boundaries and find
                // the actual element clicked (e.g. a button inside a web component).
                var path = e.composedPath();
                var el = null;
                var interactive = null;

                for (var pi = 0; pi < path.length && pi < 15; pi++) {
                    var node = path[pi];
                    if (node.nodeType !== 1) continue;
                    if (!el) el = node;
                    if (isInteractiveTag(node)) { interactive = node; break; }
                }
                if (!el) return;

                // Clickable card heuristic: when no interactive ancestor is found,
                // check if a nearby container has exactly one link. Common pattern
                // for cards/list-items where the heading is the primary action.
                if (!interactive) {
                    var container = el;
                    for (var ci = 0; ci < 6 && container; ci++) {
                        container = container.parentElement;
                        if (!container) break;
                        var links = container.querySelectorAll('a[href], a[role=link], a[tabindex]');
                        if (links.length === 1) { interactive = links[0]; break; }
                        if (links.length > 1) break;
                    }
                }
                if (!interactive) interactive = el;

                var tag = interactive.tagName.toLowerCase();

                // Radio buttons get special handling with ordinal index
                if (tag === 'input' && interactive.type === 'radio') {
                    postAction({
                        type: 'radio',
                        radioIndex: getRadioIndex(interactive),
                        radioValue: interactive.value || '',
                        groupLabel: getRadioGroupLabel(interactive)
                    });
                    return;
                }

                // Skip clicks on inputs/textareas (those generate type events)
                if ((tag === 'input' && interactive.type !== 'button' && interactive.type !== 'submit'
                     && interactive.type !== 'reset' && interactive.type !== 'checkbox')
                    || tag === 'textarea') {
                    return;
                }
                // Skip clicks on select/option (the change event captures the selection)
                if (tag === 'select' || tag === 'option' || tag === 'optgroup') return;
                // Skip clicks inside a web component that wraps a <select> (e.g. IDS dropdown)
                var clickRoot = interactive.getRootNode();
                if (clickRoot instanceof ShadowRoot && clickRoot.querySelector('select')) return;

                var trigger = findDropdownTrigger(interactive);
                if (trigger) {
                    var trigText = getVisibleText(trigger);
                    var trigTag = trigger.tagName.toLowerCase();
                    postAction({
                        type: 'hover',
                        selector: getSelector(trigger),
                        tag: trigTag,
                        role: getRole(trigger),
                        label: getLabel(trigger),
                        text: trigText,
                        textUnique: isTextUnique(trigText, trigTag),
                        testId: trigger.getAttribute('data-testid') || '',
                        placeholder: trigger.placeholder || ''
                    });
                }

                var visText = getVisibleText(interactive);
                postAction({
                    type: 'click',
                    selector: getSelector(interactive),
                    tag: tag,
                    role: getRole(interactive),
                    label: getLabel(interactive),
                    text: visText,
                    textUnique: isTextUnique(visText, tag),
                    href: interactive.href || '',
                    testId: interactive.getAttribute('data-testid') || '',
                    placeholder: interactive.placeholder || '',
                    inputType: interactive.type || ''
                });
            }, true);

            // --- Right-click capture (extract metadata for context menu actions) ---
            document.addEventListener('contextmenu', function(e) {
                var path = e.composedPath();
                var el = null;
                var interactive = null;
                for (var i = 0; i < path.length; i++) {
                    var node = path[i];
                    if (!node.tagName) continue;
                    if (!el) el = node;
                    if (!interactive && isInteractiveTag(node)) interactive = node;
                    if (interactive) break;
                }
                var target = interactive || el || e.target;
                var tag = target.tagName.toLowerCase();
                var visText = getVisibleText(target);
                window.__trowserRightClickData = {
                    tag: tag,
                    text: visText || getLabel(target) || '',
                    role: getRole(target),
                    label: getLabel(target),
                    inputType: target.type || '',
                    href: target.href || '',
                    selector: getSelector(target),
                    testId: target.getAttribute('data-testid') || '',
                    placeholder: target.placeholder || ''
                };
            }, true);

            // --- Type capture (debounced, with flush on focus-loss and unload) ---
            var typeTimers = new Map();
            var typeElements = new Map();

            function flushType(el) {
                var key = getSelector(el);
                var timerId = typeTimers.get(key);
                if (timerId !== undefined) {
                    clearTimeout(timerId);
                    typeTimers.delete(key);
                    typeElements.delete(key);
                    var tag = el.tagName.toLowerCase();
                    postAction({
                        type: 'type',
                        selector: key,
                        tag: tag,
                        label: getLabel(el),
                        value: el.value || el.innerText || '',
                        inputType: el.type || '',
                        testId: el.getAttribute('data-testid') || '',
                        placeholder: el.placeholder || ''
                    });
                }
            }

            function flushAllTypes() {
                typeElements.forEach(function(el) { flushType(el); });
            }

            document.addEventListener('input', function(e) {
                var el = e.target;
                var tag = el.tagName.toLowerCase();
                if (tag !== 'input' && tag !== 'textarea' && !el.isContentEditable) return;
                if (el.type === 'checkbox' || el.type === 'radio') return;

                var key = getSelector(el);
                clearTimeout(typeTimers.get(key));
                typeElements.set(key, el);
                typeTimers.set(key, setTimeout(function() {
                    typeTimers.delete(key);
                    typeElements.delete(key);
                    postAction({
                        type: 'type',
                        selector: key,
                        tag: tag,
                        label: getLabel(el),
                        value: el.value || el.innerText || '',
                        inputType: el.type || '',
                        testId: el.getAttribute('data-testid') || '',
                        placeholder: el.placeholder || ''
                    });
                }, 500));
            }, true);

            // Flush pending type when user leaves a field
            document.addEventListener('focusout', function(e) {
                var el = e.target;
                if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) {
                    flushType(el);
                }
            }, true);

            // Flush all pending types on change (covers fields updated without input events)
            document.addEventListener('change', function(e) {
                var el = e.target;
                var tag = el.tagName.toLowerCase();
                if (tag === 'select') return; // handled by select capture below
                if (tag === 'input' || tag === 'textarea') {
                    flushType(el);
                }
            }, true);

            // --- Scroll capture (debounced). Always posted; CapturedActionRouting
            //     in C# decides sinks. Today scroll is Mirror-only — replay
            //     scripts omit it (viewport/layout differs, steps just get longer). ---
            var scrollTimer = null;
            var pendingScroll = null;
            function flushScroll() {
                if (!pendingScroll) return;
                postAction(pendingScroll);
                pendingScroll = null;
                if (scrollTimer) { clearTimeout(scrollTimer); scrollTimer = null; }
            }
            function onScroll(e) {
                var t = e.target;
                var isDoc = !t || t === window || t === document
                    || t === document.documentElement || t === document.body;
                if (isDoc) {
                    pendingScroll = {
                        type: 'scroll',
                        scrollX: Math.round(window.scrollX || window.pageXOffset || 0),
                        scrollY: Math.round(window.scrollY || window.pageYOffset || 0)
                    };
                } else if (t && t.nodeType === 1) {
                    pendingScroll = {
                        type: 'scroll',
                        selector: getSelector(t),
                        tag: t.tagName.toLowerCase(),
                        testId: t.getAttribute('data-testid') || '',
                        label: getLabel(t),
                        scrollX: Math.round(t.scrollLeft || 0),
                        scrollY: Math.round(t.scrollTop || 0)
                    };
                }
                if (scrollTimer) clearTimeout(scrollTimer);
                scrollTimer = setTimeout(flushScroll, 150);
            }
            document.addEventListener('scroll', onScroll, true);
            window.addEventListener('scroll', onScroll, true);

            // Flush everything before page unloads (navigation, redirect, etc.)
            window.addEventListener('beforeunload', function() { flushAllTypes(); flushScroll(); });

            // --- Select capture ---
            document.addEventListener('change', function(e) {
                var el = e.target;
                if (el.tagName.toLowerCase() !== 'select') return;

                postAction({
                    type: 'select',
                    selector: getSelector(el),
                    label: getLabel(el),
                    value: el.value,
                    selectedText: el.options[el.selectedIndex] ? el.options[el.selectedIndex].text : '',
                    testId: el.getAttribute('data-testid') || '',
                    placeholder: ''
                });
            }, true);

            // --- Key capture (non-character keys only) ---
            var captureKeys = ['Tab', 'Enter', 'Escape', 'Backspace', 'Delete',
                               'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
                               'Home', 'End', 'PageUp', 'PageDown'];

            document.addEventListener('keydown', function(e) {
                var hasModifier = e.ctrlKey || e.altKey || e.metaKey;
                var isSpecialKey = captureKeys.indexOf(e.key) >= 0;

                if (!isSpecialKey && !hasModifier) return;

                // Skip modifier-only presses
                if (['Control', 'Alt', 'Shift', 'Meta'].indexOf(e.key) >= 0) return;

                // Skip clipboard/editing shortcuts -- the result is captured by input events
                if ((e.ctrlKey || e.metaKey) && 'vVcCxXaAzZyY'.indexOf(e.key) >= 0) return;

                var tag = e.target.tagName.toLowerCase();
                var isInput = (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable);

                // In inputs, only capture Tab, Enter, Escape, or modifier combos
                if (isInput && !hasModifier && !(['Tab', 'Enter', 'Escape'].indexOf(e.key) >= 0)) return;

                postAction({
                    type: 'key',
                    key: e.key,
                    ctrlKey: e.ctrlKey,
                    altKey: e.altKey,
                    shiftKey: e.shiftKey,
                    metaKey: e.metaKey,
                    selector: getSelector(e.target),
                    tag: tag
                });
            }, true);

            // --- Attach listeners to shadow roots too ---
            function hookShadowRoot(shadowRoot) {
                shadowRoot.addEventListener('click', document.onclick, true);
            }

            var roots = collectShadowRoots(document);
            // Shadow roots share the same document event capture for most events,
            // but we mark that we've hooked so re-injection is idempotent.
        })();
        """;
}
