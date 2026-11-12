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
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
    #region Tool Definitions

    private static readonly HashSet<string> ChatTools =
    [
        "browser_snapshot", "get_test_heuristics", "browser_scripting_help", "browser_inspiration", "browser_coverage",
        "browser_journal_add", "browser_journal_get", "browser_journal_export", "browser_journal_import", "browser_journal_update", "browser_journal_delete",
        "browser_compact", "browser_session_memory",
        "browser_decide", "browser_decisions"
    ];

    /// <summary>
    /// Built-in everyday testing pack: interact, observe, quality audits, security overview
    /// (<c>browser_security</c>) and Retire.js-only CVE scan (<c>browser_security_js_libraries</c>),
    /// screenshot, journal, and optional C# scripts.
    /// Specialist scanners, peers, identities, monkey, and <c>auto_scan</c> live in Full.
    /// </summary>
    private static readonly HashSet<string> EconomicalTools =
    [
        "browser_snapshot", "browser_state_refresh", "browser_diff_state",
        "browser_navigate", "browser_go_back", "browser_go_forward", "browser_force_navigate",
        "browser_click", "browser_click_at", "browser_drag", "browser_type", "browser_upload", "browser_select_option",
        "browser_hover", "browser_press_key", "browser_scroll",
        "browser_take_screenshot", "browser_screenshot_compare",
        "browser_find", "browser_find_clear",
        "browser_text", "browser_extract", "browser_property",
        "browser_wait", "browser_wait_for_final_navigation", "browser_wait_for_idle", "browser_wait_for_network",
        "browser_tabs", "browser_new_tab", "browser_close_tab", "browser_switch_tab",
        "browser_dialog", "browser_handle_dialog",
        "browser_page_text", "browser_page_text_all", "browser_page_text_screen_reader",
        "browser_page_source", "browser_structured_text",
        "browser_console", "browser_console_clear",
        "browser_network", "browser_network_clear", "browser_network_har",
        "browser_downloads", "browser_wait_for_download", "browser_assert_download",
        "browser_clear_all", "browser_clear_session", "browser_storage",
        "browser_viewport", "browser_emulation", "browser_trace",
        "browser_fetch", "browser_fetch_batch", "browser_header_overrides", "browser_execute_js", "browser_run_script",
        "browser_accessibility", "browser_tab_order", "browser_performance",
        "browser_validate_html", "browser_seo", "browser_check_links",
        "browser_compatibility", "browser_consistency", "browser_third_party",
        "browser_audit_all",
        "browser_resource_snapshot", "browser_resource_compare", "browser_resource_probe",
        "browser_network_throttle",
        "browser_security",
        "browser_security_js_libraries",
        "browser_assert_text", "browser_assert_element", "browser_assert_url", "browser_assert_title",
        "browser_journal_add", "browser_journal_get", "browser_journal_export", "browser_journal_import", "browser_journal_update", "browser_journal_delete",
        "browser_compact", "browser_session_memory",
        "browser_inspiration", "browser_coverage", "browser_test_data",
        "browser_point", "browser_pointers", "browser_checkpoint",
        "browser_decide", "browser_decisions",
        "browser_repro_capture",
        "browser_record_start", "browser_record_status", "browser_record_stop",
        "browser_ping", "browser_abort",
        "get_test_heuristics", "browser_scripting_help", "browser_send_message"
    ];

    /// <summary>
    /// Default external MCP pack (<c>?mode=core</c>): interact, observe, quality audits,
    /// and a basic security scan. Specialist scanners and intercept live in the security pack.
    /// Built-in Economical is a separate allow-list (no auto_scan / extra security tools;
    /// includes <c>browser_take_screenshot</c>).
    /// </summary>
    private static readonly HashSet<string> CoreTools =
    [
        "browser_snapshot", "browser_state_refresh", "browser_diff_state",
        "browser_navigate", "browser_go_back", "browser_go_forward", "browser_force_navigate",
        "browser_click", "browser_click_at", "browser_drag", "browser_type", "browser_upload", "browser_select_option",
        "browser_hover", "browser_press_key", "browser_scroll",
        "browser_find", "browser_find_clear",
        "browser_text", "browser_extract", "browser_property",
        "browser_wait", "browser_wait_for_final_navigation", "browser_wait_for_idle", "browser_wait_for_network",
        "browser_tabs", "browser_new_tab", "browser_close_tab", "browser_switch_tab",
        "browser_dialog", "browser_handle_dialog",
        "browser_page_text", "browser_page_text_all", "browser_page_text_screen_reader",
        "browser_page_source", "browser_structured_text",
        "browser_console", "browser_console_clear",
        "browser_network", "browser_network_clear", "browser_network_har",
        "browser_downloads", "browser_wait_for_download", "browser_assert_download",
        "browser_clear_all", "browser_clear_session", "browser_storage",
        "browser_viewport", "browser_emulation", "browser_trace",
        "browser_fetch", "browser_fetch_batch", "browser_header_overrides", "browser_execute_js", "browser_run_script",
        "browser_accessibility", "browser_tab_order", "browser_performance",
        "browser_validate_html", "browser_seo", "browser_check_links",
        "browser_compatibility", "browser_consistency", "browser_third_party",
        "browser_audit_all",
        "browser_screenshot_compare",
        "browser_resource_snapshot", "browser_resource_compare", "browser_resource_probe",
        "browser_network_throttle",
        "browser_security", "browser_security_js_libraries", "browser_security_auto_scan",
        "browser_security_headers", "browser_security_shadow", "browser_shadow_check", "browser_laws", "browser_security_tech_stack",
        "browser_assert_text", "browser_assert_element", "browser_assert_url", "browser_assert_title",
        "browser_journal_add", "browser_journal_get", "browser_journal_export", "browser_journal_import", "browser_journal_update", "browser_journal_delete",
        "browser_inspiration", "browser_coverage", "browser_test_data",
        "browser_point", "browser_pointers", "browser_checkpoint",
        "browser_decide", "browser_decisions",
        "browser_repro_capture",
        "browser_record_start", "browser_record_status", "browser_record_stop",
        "browser_ping", "browser_abort",
        "get_test_heuristics", "browser_scripting_help", "browser_send_message"
    ];

    /// <summary>
    /// Core pack must stay under <see cref="Chat.LlmToolExecutor.CopilotMaxTools"/> so GitHub Copilot
    /// (and OpenAI-style 128-tool caps) keep journal, console, network, and interact tools.
    /// </summary>
    internal static bool IsCoreTool(string toolName) => CoreTools.Contains(toolName);

    /// <summary>
    /// Map common hallucinated names (<c>browser_note</c>, <c>browser_log</c>, <c>browser_journal</c>)
    /// onto the real journal tools so Chat still records notes when the model invents an alias.
    /// </summary>
    internal static string CanonicalToolName(string toolName, JsonElement args)
    {
        switch (toolName)
        {
            case "browser_log":
            case "browser_note":
                return "browser_journal_add";
            case "browser_journal":
                if (HasJournalWriteFields(args))
                    return "browser_journal_add";
                if (!string.IsNullOrWhiteSpace(GetString(args, "format")) ||
                    !string.IsNullOrWhiteSpace(GetString(args, "path")))
                    return "browser_journal_export";
                return "browser_journal_get";
            default:
                return toolName;
        }
    }

    private static bool HasJournalWriteFields(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object)
            return false;

        foreach (var key in new[]
                 {
                     "note", "text", "title", "kind", "severity", "evidence", "steps", "actual", "expected",
                     "priority", "oracle", "notes", "tags", "screenshot"
                 })
        {
            if (args.TryGetProperty(key, out var v) && v.ValueKind is not JsonValueKind.Undefined and not JsonValueKind.Null)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Tools omitted from every <c>tools/list</c>. Screenshot is listed in built-in
    /// Economical/Full and external security; Chat and Core omit it via their allow-lists.
    /// </summary>
    private static readonly HashSet<string> HiddenFromLlm = [];

    /// <summary>Built-in AI Assistant only — hidden from external MCP clients.</summary>
    private static readonly HashSet<string> BuiltInOnlyTools =
    [
        "browser_compact",
        "browser_session_memory"
    ];

    private bool IsToolInMode(string toolName, InteractionMode mode) => mode switch
    {
        InteractionMode.Chat => ChatTools.Contains(toolName),
        InteractionMode.Economical => EconomicalTools.Contains(toolName),
        _ => true
    };

    /// <summary>
    /// Core is the allow-list. Security (and legacy <c>full</c>) is the complete non-hidden surface.
    /// </summary>
    private static bool IsToolInExternalPack(string toolName, ExternalMcpMode pack) =>
        pack != ExternalMcpMode.Core || CoreTools.Contains(toolName);

    private bool IsToolInCurrentSurface(string toolName) =>
        (!BuiltInOnlyTools.Contains(toolName) || !ExternalAgentSurface)
        && (ExternalAgentSurface
            ? IsToolInExternalPack(toolName, EffectivePack)
            : IsToolInMode(toolName, EffectiveMode));

    private bool IsToolAvailable(string toolName) =>
        !HiddenFromLlm.Contains(toolName)
        && IsToolInCurrentSurface(toolName)
        && (!SafeMode || !SafeModePolicy.IsToolAlwaysBlocked(toolName));

    private string ToolUnavailableMessage(string toolName)
    {
        if (!ExternalAgentSurface)
        {
            if (EffectiveMode == InteractionMode.Chat)
                return $"Tool '{toolName}' is not available in Chat mode. Ask the user to switch to Economical (everyday testing) or Full (security/specialist tools) in Settings → Interaction Mode.";
            if (EffectiveMode == InteractionMode.Economical)
                return $"Tool '{toolName}' is not available in Economical mode. Ask the user to switch to Full (security/specialist tools) in Settings → Interaction Mode.";
        }

        return $"Tool '{toolName}' is not available in {EffectiveSurfaceLabel} mode.";
    }

    internal List<object> GetToolDefinitions(InteractionMode mode) =>
        FilterToolDefinitions(name => IsToolInMode(name, mode));

    internal List<object> GetListedToolDefinitions() =>
        FilterToolDefinitions(IsToolInCurrentSurface);

    private List<object> FilterToolDefinitions(Func<string, bool> include)
    {
        var all = GetAllToolDefinitions();

        return all.Where(t =>
        {
            var json = JsonSerializer.Serialize(t, CompactJson);
            var doc = JsonDocument.Parse(json);
            var name = doc.RootElement.GetProperty("name").GetString();
            if (name == null || HiddenFromLlm.Contains(name)) return false;
            return include(name);
        }).ToList();
    }

    private List<object> GetAllToolDefinitions() =>
    [
        Tool("browser_snapshot",
            "Page state: URL, title, headings, frames[], interactive elements with ref numbers, errors. " +
            "Call first before acting; use refs in other tools. Not page text (use browser_page_text). " +
            "Default visible-only, viewport-first, limit 150 (truncated hint when capped). fullElements or limit=0 for all. format=compact for slimmer fields.",
            Schema(
                ("selector", SStr("CSS selector to scope elements to those inside matching container(s)")),
                ("frame", SStr("Same-origin iframe: frameId from frames[], iframe name, or CSS selector of the <iframe>")),
                ("tag", SStr("Filter elements by tag name: input, button, a, select, textarea")),
                ("type", SStr("Filter elements by type or ARIA role: text, checkbox, submit, link, tab")),
                ("q", SStr("Filter elements by text/label search (case-insensitive)")),
                ("limit", SInt("Max interactive elements (default 150; 0 = no cap unless fullElements)")),
                ("fullElements", SBool("Return all interactive elements (ignore default cap)")),
                ("format", SStr("compact — smaller element objects and interactiveElementsLines pipe rows")),
                ("visible", SBool("Only return visible elements (default: true). Set to false to include hidden elements (ref: -1)."))
            )),

        Tool("browser_state_refresh",
            "Force a full page state rescan. Use after DOM mutations (e.g. clicking buttons that add/remove elements, " +
            "dynamic content loading) when browser_snapshot returns empty or stale interactive elements. " +
            "Waits briefly for DOM to stabilize before scanning. Returns the same data as browser_snapshot with refreshed:true.",
            Schema()),

        Tool("browser_diff_state",
            "Compare two stored page snapshots by refGeneration (from browser_snapshot / GET /api/state). " +
            "Returns elements added and removed (by CSS selector), text/value changes on matching selectors, URL/title deltas, " +
            "and new console/network error lines. Snapshots are captured whenever interactive elements are rescanned (max ~96 per session).",
            Schema(
                ("before", SInt("Earlier refGeneration number")),
                ("after", SInt("Later refGeneration number")),
                ("tabIndex", SInt("Optional tab index; defaults to active tab"))
            ),
            required: ["before", "after"]),

        Tool("browser_navigate",
            "Navigate to a URL, or move backward/forward in session history (Chrome DevTools Page.navigateToHistoryEntry — " +
            "works for SPA/hash history where history.back() in execute-js can hang). Same URL without reload uses fresh GET (Page.navigate), not Reload (which re-POSTs forms).",
            Schema(
                ("url", SStr("URL to open (required unless action is set). Scheme optional; https:// is prepended when missing.")),
                ("action", SStr("Session history: 'back' or 'forward' (omit url when set).")),
                ("reload", SBool("When true and url matches current address, browser Reload (may re-submit POST). Default: fresh GET.")),
                ("ignoreCertificateErrors", SBool("Accept invalid TLS certificates for this navigation (training/lab sites)."))
            )),

        Tool("browser_go_back",
            "Navigate back in browser history. Fails if there is no history to go back to.",
            Schema()),

        Tool("browser_go_forward",
            "Navigate forward in browser history. Fails if there is no history to go forward to.",
            Schema()),

        Tool("browser_force_navigate",
            "Recover from a frozen page (infinite loop, DoS script, resource exhaustion) when normal navigation and MCP are stuck. " +
            "Uses CDP Runtime.terminateExecution (optional) + Page.navigate — bypasses the page JS event loop. " +
            "The POST /mcp tools/call for this tool bypasses the API gate (like POST /api/force-navigate) so it works while another call holds the gate. " +
            "Prefer url about:blank for a clean slate.",
            Schema(
                ("url", SStr("Target URL (e.g. about:blank). Scheme optional; https:// prepended when missing.")),
                ("terminateScripts", SBool("Call Runtime.terminateExecution before Page.navigate (default true)."))
            ),
            required: ["url"]),

        Tool("browser_click",
            "Click an element (ref preferred, or selector/semantic locator). Auto-waits on navigation links. " +
            "button:'right' for context menu; clickCount:2 for double-click. Pass frame for same-origin iframes.",
            ElementSchema(
                ("button", SStr("Mouse button: 'left' (default), 'right', or 'middle'")),
                ("clickCount", SInt("Number of clicks: 1 (default) for single click, 2 for double-click"))
            )),

        Tool("browser_click_at",
            "CDP click at viewport x/y (CSS pixels). Hits the topmost painted target, including cross-origin iframe " +
            "content, without DOM/ref access inside the frame. Prefer browser_click when refs exist.",
            Schema(
                ("x", SNum("Viewport X in CSS pixels")),
                ("y", SNum("Viewport Y in CSS pixels")),
                ("button", SStr("Mouse button: 'left' (default), 'right', or 'middle'")),
                ("clickCount", SInt("Number of clicks (default 1)"))
            )),

        Tool("browser_drag",
            "Drag from one element to another (HTML5 DragEvent when draggable, else CDP mouse; html5 true/false to force). " +
            "Provide from+to (nested ref/selector/locator) or flat fromRef/fromSelector + toRef/toSelector.",
            Schema(
                ("from", SObj("Source element: {ref|selector|role|label|...}")),
                ("to", SObj("Target element: {ref|selector|role|label|...}")),
                ("fromRef", SInt("Source element ref (flat alternative)")),
                ("fromSelector", SStr("Source CSS selector (flat alternative)")),
                ("toRef", SInt("Target element ref (flat alternative)")),
                ("toSelector", SStr("Target CSS selector (flat alternative)")),
                ("steps", SInt("Intermediate mouseMoved steps (default 10)")),
                ("html5", SBool("true=HTML5 only, false=CDP only; omit=auto")),
                ("frame", SStr("Optional same-origin iframe scope for both ends")),
                ("timeout", SInt("Wait timeout in ms"))
            )),

        Tool("browser_type",
            "Type into an input/textarea/contenteditable (clears first). Content: value or text (aliases), or html for rich editors. " +
            "Target with ref (preferred) or locator — do not use text as a locator; use byText.",
            TypeElementSchema(
                ("value", SStr("Text to type into the element (preferred; alias of 'text')")),
                ("text", SStr("Alias for value — text to type (REST-shaped). Not a locator; use byText for that.")),
                ("html", SStr("HTML content to insert (contenteditable elements only). If provided, inserts rich HTML instead of plain text."))
            )),

        Tool("browser_upload",
            "Assign local file(s) to a file input (CDP). Absolute host paths, or base64+fileName. Optional submit:true. Blocked in safe mode.",
            ElementSchema(
                ("path", SStr("Single absolute file path on the Trowser host machine")),
                ("paths", SArr("Array of absolute file paths for multi-file inputs")),
                ("base64", SStr("File bytes as base64 (written to a temp file, then assigned)")),
                ("fileName", SStr("Original name when using base64 (default: upload.bin)")),
                ("submit", SBool("Submit parent form after assigning files (default: false)")),
                ("timeout", SInt("Wait timeout in ms for the file input (default: use automation default)"))
            )),

        Tool("browser_select_option",
            "Select a dropdown option by value. Target with ref (preferred) or selector/semantic locator.",
            ElementSchema(("value", SStr("The option value to select"))),
            required: ["value"]),

        Tool("browser_hover",
            "Hover over an element (tooltips/menus). Target with ref (preferred) or selector/semantic locator.",
            ElementSchema()),

        Tool("browser_press_key",
            "Send a key press, optionally to a focused/targeted element. Keys: Enter, Tab, Escape, arrows, Home, End, etc.",
            OptionalElementSchema(
                ("key", SStr("Key to press: Enter, Tab, Escape, Backspace, ArrowUp, ArrowDown, etc.")),
                ("modifiers", new Dictionary<string, object> {
                    ["type"] = "array",
                    ["items"] = new Dictionary<string, object> { ["type"] = "string" },
                    ["description"] = "Modifier keys: Shift, Control, Alt"
                })
            ),
            required: ["key"]),

        Tool("browser_scroll",
            "Scroll the page (direction) or bring a targeted element into view (scrollIntoView).",
            OptionalElementSchema(
                ("direction", SStr("Scroll direction: up, down, top, bottom (default: down)")),
                ("scrollIntoView", SBool("Scroll the targeted element into view")),
                ("timeout", SInt("Timeout in ms (default: 10000). Prevents hang if the page is unresponsive."))
            )),

        Tool("browser_take_screenshot",
            "Capture a screenshot of the page or an element. Two purposes: " +
            "'journal' (default) saves the file and attaches it to the session journal — no image bytes in the tool result (cheap). " +
            "'inspect' returns the image so you can look at layout/visual bugs — expensive; use jpeg; only when a snapshot is not enough. " +
            "Optional ref/selector + padding. Response always includes the saved path for browser_screenshot_compare / journal.",
            OptionalElementSchema(
                ("purpose", SStr("'journal' (default: save + attach to journal, no image in the result) or 'inspect' (return image to look at it)")),
                ("note", SStr("Optional caption stored on the journal screenshot entry")),
                ("padding", SInt("Extra pixels around the element (0-200). Only for element screenshots")),
                ("format", SStr("Image format: 'png' (lossless) or 'jpeg' (smaller). Default png for journal, jpeg for inspect.")),
                ("quality", SInt("JPEG quality 1-100 (default: 80). Only used with format='jpeg'"))
            )),

        Tool("browser_screenshot_compare",
            "Compare two screenshots pixel-by-pixel for visual regression testing. " +
            "Highlights differences with a red overlay on the 'after' image, dims unchanged pixels. " +
            "Pass 'before' as a file path from GET /api/screenshot or a prior browser_take_screenshot call. " +
            "If 'after' is omitted, the current page is captured automatically — " +
            "ideal workflow: screenshot before action, perform action, compare.\n\n" +
            "Returns: diff image (inline), percentage of changed pixels, and pixel counts. " +
            "A match (0% diff) means the pages are visually identical within the threshold.",
            Schema(
                ("before", SStr("File path to the 'before' screenshot (from GET /api/screenshot or browser_take_screenshot)")),
                ("after", SStr("File path to the 'after' screenshot. If omitted, captures current page")),
                ("threshold", SInt("Pixel difference threshold 0-255 (default: 30). Lower = more sensitive"))
            ),
            required: ["before"]),

        Tool("browser_text",
            "Get the inner text of a specific element. Pierces shadow DOM boundaries. " +
            "Target using 'ref', 'selector', or semantic locator.",
            ElementSchema()),

        Tool("browser_extract",
            "Extract structured data from repeating elements (table auto, field map, or simple text list). selector required; optional fields/@attr.",
            Schema(
                ("selector", SStr("CSS selector for the container elements or table to extract from")),
                ("fields", new Dictionary<string, object> {
                    ["type"] = "object",
                    ["description"] = "Optional field mapping: {fieldName: \"subSelector\", ...}. " +
                        "Sub-selectors find elements within each container. Use @attr suffix for attributes (e.g. \"a@href\").",
                    ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" }
                }),
                ("limit", SInt("Maximum number of items to return (default: no limit)"))
            ),
            required: ["selector"]),

        Tool("browser_find",
            "Search visible page text (query or regex). Returns matches with context/selector/bounds; optional scrollTo/highlight.",
            Schema(
                ("text", SStr("The text to search for")),
                ("caseSensitive", SBool("Case-sensitive search (default: false)")),
                ("regex", SBool("Treat text as a regular expression (default: false)")),
                ("scrollTo", SInt("Scroll to the Nth match (0-based index)")),
                ("highlight", SBool("Highlight all matches on the page with yellow background (default: false)")),
                ("visibleOnly", SBool("Only search visible text (default: true). Set to false to include hidden/off-screen elements."))
            ),
            required: ["text"]),

        Tool("browser_find_clear",
            "Remove all text search highlights previously added by browser_find with highlight=true.",
            Schema()),

        Tool("browser_page_text",
            "Get all visible text on the page (document.body.innerText). Useful for searching or verifying page content.",
            Schema()),

        Tool("browser_page_text_all",
            "Get all text on the page including hidden/off-screen content (every text node; one line per non-empty segment). " +
            "Includes shadow DOM; excludes script/style/noscript/template. Use for thorough proof-reading beyond visible text.",
            Schema()),

        Tool("browser_page_text_screen_reader",
            "Get screen-reader-oriented strings: alt, aria-label, resolved aria-labelledby and aria-describedby, title, " +
            "and SVG title/desc elements, including inside shadow DOM. Each line is prefixed with [kind].",
            Schema()),

        Tool("browser_page_source",
            "Get the full HTML source of the current page (document.documentElement.outerHTML). " +
            "Warning: can be very large and token-expensive. Prefer browser_snapshot for most inspections.",
            Schema()),

        Tool("browser_execute_js",
            "Run JavaScript in the page and return the string result (awaits Promises; multi-statement auto-IIFE). " +
            "Prefer browser_fetch for HTTP and browser_text/property for DOM. " +
            "Do not fetch JS bundles, source maps, or other large static assets here (WebView2 often hangs past 30s) — " +
            "use browser_fetch with serverSide:true, or browser_security_js_audit / browser_security_secrets_harvest. " +
            "Empty string = undefined/null.",
            Schema(
                ("script", SStr("JavaScript expression or script body to execute")),
                ("timeout", SInt("Max wait for Promise resolution in ms (default: 30000)"))
            ),
            required: ["script"]),

        Tool("browser_accessibility",
            "Run a WCAG accessibility audit using axe-core. Returns violations with impact, affected elements, and remediation guidance.",
            Schema(
                ("level", SStr("WCAG level: A, AA, or AAA (default: AA)")),
                ("selector", SStr("CSS selector to scope the audit to a page section"))
            )),

        Tool("browser_tab_order",
            "Verify keyboard tab order with real Tab and Shift+Tab (CDP). Auto-detects open modal dialogs " +
            "and scopes the walk to them; flags focus leaking to the page background (modal-focus-leak). " +
            "Also detects skipped in-scope controls, focus traps, reading-order jumps, and Shift+Tab inconsistencies. " +
            "REST: POST /api/tab-order.",
            Schema(
                ("selector", SStr("CSS scope (optional; default auto-detect modal or full page)")),
                ("startSelector", SStr("Element to focus before walking")),
                ("autoDetectScope", SBool("Auto-detect modal/popover scope when selector omitted (default true)")),
                ("strictScope", SBool("Error when Tab leaves scope, e.g. background under modal (default true)")),
                ("maxSteps", SInt("Max Tab/Shift+Tab steps per direction (default 150)")),
                ("checkPositiveTabIndex", SBool("Flag tabindex > 0 (default true)")),
                ("checkSkipped", SBool("Flag visible focusables not reached by Tab (default true)")),
                ("checkReadingOrder", SBool("Flag large spatial jumps (default true)")),
                ("checkFocusTrap", SBool("Flag small Tab cycles when many focusables exist (default true)")),
                ("checkShiftTabConsistency", SBool("Compare forward vs backward order (default true)")),
                ("expectedOrder", SArr("Expected focus sequence: labels, selectors, or ref numbers")),
                ("includeSteps", SBool("Include forward/backward step lists in JSON (default true)"))
            )),

        Tool("browser_performance",
            "Measure Web Vitals performance metrics for the current page. " +
            "Returns Core Web Vitals (LCP, CLS, INP) with Good/Needs Improvement/Poor ratings, " +
            "plus TTFB, FCP, navigation timing breakdown, and resource loading summary.",
            Schema()),

        Tool("browser_resource_snapshot",
            "Take a point-in-time resource usage snapshot via CDP: JS heap (after GC), DOM node count, " +
            "event listeners, open WebSockets, and optional live HTMLElement count. " +
            "Passive — does not mutate the page. Set rememberBaseline: true to compare later with browser_resource_compare.",
            Schema(
                ("rememberBaseline", SBool("Store this snapshot for the next browser_resource_compare call (default false)")))),

        Tool("browser_resource_compare",
            "Compare a saved resource baseline to the current page after you perform actions yourself " +
            "(login flows, navigation, modal open/close, etc.). Returns structured findings like browser_resource_probe " +
            "but without replaying actions or reloading. Pass baseline from a prior snapshot, or use useRememberedBaseline: true.",
            Schema(
                ("baseline", SObj("Snapshot object from browser_resource_snapshot (heap, dom, connections, url, timestamp)")),
                ("useRememberedBaseline", SBool("Use baseline from last browser_resource_snapshot with rememberBaseline: true")),
                ("settleMs", SInt("Wait before measuring final state (default 500)")),
                ("gcBeforeFinal", SBool("Force GC before final sample (default true)")),
                ("growthThresholdPercent", SNum("Percent growth threshold for findings (default 10)")),
                ("listenerGrowthThreshold", SInt("Absolute listener growth threshold (default 50)")),
                ("nodeGrowthThreshold", SInt("Absolute DOM node growth threshold (default 100)")))),

        Tool("browser_resource_probe",
            "Detect possible memory/resource leaks by repeating the same actions or page reloads, forcing GC, and comparing metrics. " +
            "Use browser_resource_compare instead when you perform actions yourself between before/after snapshots. " +
            "Requires either \"actions\" (batch format: click/type with ref) or \"reloadBetweenIterations\": true. " +
            "Click/type actions require safetyMode: active.",
            Schema(
                ("actions", SArr("Actions to replay each iteration: [{action, ref|selector|byText, ...}]")),
                ("iterations", SInt("Measurement iterations after baseline (default 5)")),
                ("reloadBetweenIterations", SBool("Reload current URL each iteration — good for refresh-leak tests (default false)")),
                ("gcBetweenIterations", SBool("Force GC before each sample (default true)")),
                ("settleMs", SInt("Wait after actions before measuring (default 500)")),
                ("growthThresholdPercent", SNum("Percent growth threshold for findings (default 10)")),
                ("listenerGrowthThreshold", SInt("Absolute listener growth threshold (default 50)")),
                ("nodeGrowthThreshold", SInt("Absolute DOM node growth threshold (default 100)"))
            )),

        Tool("browser_security",
            "Passive security overview on the current page (same modules as Quicktests → 1 Security Scan): " +
            "tech stack, Retire.js CVEs, HTTP headers, CORS, DOM XSS patterns, mixed content, cookies, source maps, " +
            "web storage, HTTP methods, and path discovery. Retire.js only: browser_security_js_libraries. " +
            "REST: POST /api/security.",
            Schema(
                ("includeDiscover", SBool("Run endpoint discovery wordlist (default true)")),
                ("includeMethods", SBool("Probe HTTP methods on document URL (default true)")),
                ("wordlist", SStr("Discover wordlist when includeDiscover (default common)")),
                ("delayMs", SInt("Discover delay between probes in ms (default 0)"))
            )),

        Tool("browser_security_js_libraries",
            "Retire.js scan for known vulnerable JavaScript library versions on the current page. " +
            "Detects versions via live-DOM globals, script URLs, and fetched bundle patterns. " +
            "For supply chain / OSV use browser_security_supply_chain_scan. REST: POST /api/security/js-libraries.",
            Schema()),

        Tool("browser_ping",
            "Health check: alive, API port, whether a browser operation is in progress. Bypasses the gate. REST: GET /api/ping.",
            Schema()),

        Tool("browser_abort",
            "Cancel the in-flight gated operation (long scan, navigation, etc.). Bypasses the gate. REST: POST /api/abort.",
            Schema()),

        Tool("browser_security_help",
            "Short MCP security testing playbook: browse → attack surface → targeted scans → verify. No parameters.",
            Schema()),

        Tool("browser_orchestrate_list",
            "List security orchestration playbooks (gate-free read). REST: GET /api/orchestrate/playbooks.",
            Schema()),

        Tool("browser_orchestrate_dry_run",
            "Dry-run a playbook: playbookId required; same body fields as REST POST /api/orchestrate/dry-run/{id}.",
            Schema(
                ("playbookId", SStr("Playbook id from browser_orchestrate_list")),
                ("safetyMode", SStr("Safety mode for planned steps"))
            )),

        Tool("browser_orchestrate_run",
            "Run a security playbook. playbookId required. Set async:true to return immediately and poll GET /api/orchestrate/runs/{runId}. " +
            "REST: POST /api/orchestrate/{playbookId}.",
            Schema(
                ("playbookId", SStr("Playbook id from browser_orchestrate_list")),
                ("async", SBool("When true, start in the background and return poll metadata (default false)")),
                ("safetyMode", SStr("Safety mode: passive | safe | active | aggressive"))
            )),

        Tool("browser_security_headers",
            "Analyze HTTP response headers for security misconfigurations. " +
            "Checks Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, " +
            "Referrer-Policy, Permissions-Policy, information leakage (Server, X-Powered-By), " +
            "and deprecated headers. Based on OWASP best practices. REST: POST /api/security/headers.",
            Schema()),

        Tool("browser_security_cors",
            "Audit CORS configuration by probing with various Origin headers. " +
            "Default: document URL only (in-browser XHR preflight). " +
            "Set includeAttackSurfaceUrls: true or sweep: true for multi-endpoint sweep " +
            "(document + /api/*, /graphql, /rest/* from attack surface). " +
            "REST: POST /api/security/cors.",
            Schema(
                ("includeAttackSurfaceUrls", SBool("Multi-endpoint sweep using attack-surface API URLs (default false)")),
                ("sweep", SBool("Alias for includeAttackSurfaceUrls")),
                ("urls", SArr("Explicit URLs to probe in sweep mode")),
                ("maxUrls", SInt("Max endpoints in sweep (default 14)")),
                ("includeBrowserCookies", SBool("Attach session cookies in server-side sweep probes (default true)")),
                ("includeCredentialsProbe", SBool("Explicit reflected-origin + Allow-Credentials probe with session cookies (default true)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)"))
            )),

        Tool("browser_security_forced_error_scan",
            "Stack-trace / verbose error disclosure scan: malformed JSON POST to API endpoints. " +
            "REST: POST /api/security/forced-error-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("urls", SArr("Optional explicit endpoint URLs")),
                ("payloads", SArr("Payload set: truncated_json, empty_body, xml_instead_of_json, oversized_payload, invalid_charset, null_byte_in_field, duplicate_content_type, array_instead_of_object, nested_recursion")),
                ("maxEndpoints", SInt("Max endpoints (default 12)")),
                ("includeNetworkDiscovery", SBool("Discover JSON POST endpoints from network log (default true)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)"))
            )),

        Tool("browser_security_trusted_header_bypass",
            "Trusted-proxy header bypass: replay X-Forwarded-User / X-Real-IP on 401/403 paths. " +
            "REST: POST /api/security/trusted-header-bypass. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("paths", SArr("Optional path list")),
                ("urls", SArr("Optional full URLs (alias for paths)")),
                ("headers", SArr("Custom header names to test (e.g. X-Original-URL, X-Rewrite-URL)")),
                ("headerSets", SArr("Custom header sets as objects { \"Header-Name\": \"value\" }")),
                ("maxTargets", SInt("Max gated paths to test (default 20)")),
                ("discoverFromAttackSurface", SBool("Merge admin/internal paths from attack surface (default true)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)"))
            )),

        Tool("browser_security_default_credential_canary",
            "Default-credential canary: small built-in wordlist against login forms/URLs. " +
            "Complements browser_security_brute_force (lockout testing). Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("loginUrls", SArr("Optional explicit login URLs")),
                ("loginUrl", SStr("Single login URL (alias for loginUrls[0])")),
                ("bodyTemplate", SStr("Optional JSON/form body with §USER§ and §PASS§ placeholders")),
                ("body", SStr("Alias for bodyTemplate")),
                ("contentType", SStr("Optional Content-Type (default application/json for JSON bodies)")),
                ("method", SStr("HTTP method (default POST)")),
                ("maxTargets", SInt("Max login targets (default 5)")),
                ("maxPairs", SInt("Max credential pairs to try (default 12; built-in list includes admin/admin123)")),
                ("includeDiscoveredCredentials", SBool("Merge credential pairs from js-audit/secrets-harvest sources (JS, page HTML, network log)")),
                ("delayMs", SInt("Delay between attempts ms (default 400)")),
                ("discoverFromPage", SBool("Detect password forms on current page (default true; false when loginUrl set)")),
                ("discoverFromNetwork", SBool("Use login URLs from network log (default true; false when loginUrl set)"))
            )),

        Tool("browser_security_discover",
            "Discover hidden endpoints, admin panels, config files, and API documentation " +
            "by probing common paths. Returns discovered paths with status codes and content types. " +
            "Useful for reconnaissance during security testing. " +
            "Always baselines an invalid path and filters uniform auth redirects (same 3xx + same Location host/path — " +
            "query stripped so SAML/OIDC IdP bounces are not false positives). " +
            "spaMode defaults to true: responses that match that baseline (same status, title, similar body length) are excluded, " +
            "and baselineNote explains the exclusion. Set spaMode or baselineFilter to false to keep shell duplicates. " +
            "API-shaped responses (json, xml, text/plain) are never auto-removed; identical ones are called out in baselineNote.",
            Schema(
                ("wordlist", SStr("Wordlist to use: 'common' (default, ~50 paths), 'full' (~150 paths), 'api' (API-focused), or omit for common")),
                ("basePath", SStr("Base path to prepend to wordlist entries (default: '/')")),
                ("delayMs", SInt("Milliseconds to wait between each request. 0 (default) = 10 parallel requests. >0 = sequential with delay (avoids 429 rate limiting)")),
                ("spaMode", SBool("Default true. Exclude SPA shell / soft-404 duplicates (status + title + similar body length). Set false to keep them; baselineNote then counts how many match the invalid-path probe. Uniform 3xx auth redirects are always filtered.")),
                ("baselineFilter", SBool("Alias for spaMode. Default true when spaMode is omitted.")),
                ("spaProbePath", SStr("Optional custom path for the SPA/auth-redirect probe (default: random under basePath)"))
            )),

        Tool("browser_security_crawl_light",
            "Light same-origin crawler: follows <a href> links and enumerates <form action> URLs (GET only, no POST submissions). " +
            "With spaMode: true, also extracts routerLink/hash routes and clicks navigation elements to discover client-side SPA routes. " +
            "By default skips logout/sign-out/SLO URLs (excludeLogout: true) so crawl does not end the session; " +
            "use excludePaths / excludeUrlPatterns / includePaths to further restrict navigation. " +
            "Populates the network log before attack-surface or auto-scan. Depth 2-3 by default; not a full Monkey Trowser pass. " +
            "REST: POST /api/security/crawl-light.",
            Schema(
                ("host", SStr("Restrict discovery/navigation to this host (default: current page)")),
                ("maxDepth", SInt("Max link depth from start page (default 2, max 5)")),
                ("maxPages", SInt("Max pages to visit (default 30, max 100)")),
                ("followLinks", SBool("Follow same-origin anchor links (default true)")),
                ("enumerateForms", SBool("Collect form action URLs (default true)")),
                ("visitFormActions", SBool("GET-navigate form actions (default true)")),
                ("delayMs", SInt("Delay between navigations in ms (default 200)")),
                ("spaMode", SBool("SPA mode: extract routerLink/hash routes and click nav elements (default true; set false for document-only crawl)")),
                ("maxInteractionsPerPage", SInt("Max click interactions per page in spaMode (default 20, max 50)")),
                ("waitAfterInteractionMs", SInt("Wait after each click for XHR/navigation (default 400)")),
                ("includePaths", SArr("Optional glob allowlist for path+query (e.g. /app/*). Empty = allow all")),
                ("excludePaths", SArr("Glob denylist for path+query (e.g. /logout, /admin/*)")),
                ("excludeUrlPatterns", SArr("Optional regex denylist matched against path+query")),
                ("excludeLogout", SBool("Skip logout/sign-out/SLO paths and logout-looking controls (default true)"))
            )),

        Tool("browser_attack_surface",
            "Map attack surface from network traffic (endpoints, methods, params, auth) with optional OpenAPI/JS enrichment, " +
            "security.txt, and spaMode live-DOM view. Browse first unless spaMode/spec-only. REST: POST /api/security/attack-surface.",
            Schema(
                ("includeParameters", SBool("Include discovered parameters: query, body, headers, path (default: true)")),
                ("includeAuth", SBool("Include authentication analysis: cookies, tokens, CSRF (default: true)")),
                ("includeResponsePatterns", SBool("Include response body structure analysis (default: true)")),
                ("host", SStr("Filter to a specific host (default: all hosts in the network log)")),
                ("includeDataUrls", SBool("Include data: URIs in the analysis (default: false — filtered to reduce noise)")),
                ("spaMode", SBool("When true, merge live interactiveElements + HTML form count (same as GET /api/state); allow empty network log")),
                ("checkSecurityTxt", SBool("When true (default), GET /.well-known/security.txt and /security.txt for the navigated page host only (RFC 9116); shown at top of report")),
                ("includeApiEnrichment", SBool("Mine OpenAPI specs (network + GET probes) + JS bundle API URL hints and merge into endpoints (default: true)")),
                ("includeOpenApiFromNetwork", SBool("Scan successful network responses for openapi/swagger JSON payloads (default: true)")),
                ("includeOpenApiProbes", SBool("GET common /openapi.json /swagger.json paths on page + API origins (default: true)")),
                ("includeJsBundleHints", SBool("Fetch script[src] bundles and scan for /api/ URLs (default: true)")),
                ("includeDevArtifactProbes", SBool("GET-probe common development/config artifacts (.env, lockfiles, .git, Docker, README) on page + API origins (default: true)")),
                ("maxProbeOrigins", SInt("Maximum distinct origins for OpenAPI GET probes (default: 6, max: 20)")),
                ("maxJsScripts", SInt("Maximum external .js files to scan for URL hints (default: 24, max: 80)")),
                ("maxJsBundleBytesPerFile", SInt("Cap bytes read per script bundle (default: 524288)")),
                ("maxJsHintPaths", SInt("Stop after this many unique URL hints from JS (default: 200)")),
                ("enrichmentHttpTimeoutMs", SInt("HTTP timeout for enrichment fetches (default: 12000)")),
                ("includeApiInventory", SBool("Include specVsObserved, versionClusters, authDelta block (default: true)")),
                ("includeAuthDeltaProbes", SBool("Session cookie vs anonymous GET probes (requires safetyMode: active, default: false)")),
                ("maxAuthDeltaProbes", SInt("Max endpoints for authDelta probes (default: 16)")),
                ("registerChainFindings", SBool("Register shadow/zombie/auth-gated findings for chain-analyze (default: true)"))
            )),

        Tool("browser_security_api_inventory",
            "OpenAPI/spec vs observed API inventory: tags paths as documented, shadow, or zombie-candidate; " +
            "groups parallel /v1 /v2 version clusters; optional authDelta probes (session-only endpoints). " +
            "REST: POST /api/security/api-inventory. Also returned as apiInventory on POST /api/security/attack-surface when includeApiInventory: true.",
            Schema(
                ("spaMode", SBool("Allow empty network log + live DOM (default: false; auto true when log empty)")),
                ("includeApiEnrichment", SBool("OpenAPI + JS bundle mining (default: true)")),
                ("includeAuthDeltaProbes", SBool("Probe anonymous vs session cookies (requires safetyMode: active)")),
                ("maxAuthDeltaProbes", SInt("Max authDelta probes (default: 16)")),
                ("registerChainFindings", SBool("Register chain findings (default: true)")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required for authDelta) | aggressive. Default: safe"))
            )),

        Tool("browser_security_clickjack_test",
            "Clickjacking / UI redressing: passive X-Frame-Options / CSP frame-ancestors plus optional active cross-origin iframe proof. " +
            "Sweep sensitive URLs from attack surface like CORS sweep. REST: POST /api/security/clickjack-test.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required for active tests) | aggressive. Default: safe")),
                ("includeActiveTest", SBool("Active cross-origin iframe load test (default: false unless safetyMode >= active)")),
                ("sweep", SBool("Alias for includeAttackSurfaceUrls multi-URL sweep")),
                ("includeAttackSurfaceUrls", SBool("Sweep document + sensitive attack-surface URLs (default: true when sweep)")),
                ("includeDefaultCandidates", SBool("Include /login /admin /checkout paths (default: true)")),
                ("maxUrls", SInt("Max URLs in sweep (default: 12)")),
                ("includeSensitiveOverlayTest", SBool("Overlay test on current page when active (default: matches active)")),
                ("sensitiveRef", SInt("Ref from browser_snapshot for overlay target")),
                ("registerChainFindings", SBool("Register clickjack-vulnerable findings (default: true)"))
            )),

        Tool("browser_security_shadow",
            "Ambient Shadow analysis on each navigation (off by default; when on: XSS, Retire.js, Headers, Network, Console errors; same-origin, GUI notifications on). " +
            "WCAG is opt-in. Named pack 'all' is headers/cookies/XSS/mixed-content/source-maps/storage/Retire.js (not WCAG/Network/Console). " +
            "enabled true/false to start/stop; omit or action:'status' for findings; action:'clear' to reset. Findings also appear on browser_snapshot.",
            Schema(
                ("enabled", SBool("Enable (true) or disable (false) Shadow. Off at startup until the user turns it on. Omit to query status/findings")),
                ("action", SStr("Action: 'status' (get findings, default when enabled is omitted), 'clear' (reset findings)")),
                ("audits", SArr("Factory default: xss, retire-js, security-headers, network, console. Named pack 'all' = headers, cookies, xss, mixed-content, source-maps, storage, retire-js (not wcag/network/console). Also: wcag, cookies, mixed-content, source-maps, storage, runtime (client-side sink/listener sensor)")),
                ("scope", SStr("URL scope: 'same-origin' (default), 'all', or a URL pattern/regex")),
                ("suggestions", SBool("Generate proactive testing suggestions alongside findings (default: true)")),
                ("category", SStr("Filter findings by category (for status queries)")),
                ("severity", SStr("Filter findings by minimum severity: 'info', 'low', 'medium', 'high', 'critical'")),
                ("laws", SBool("Enable Law invariant checks (Shadow Light on navigation, Heavy on demand). Default true when Shadow is enabled.")),
                ("lawsMining", SBool("Propose new Laws from browsing patterns (Experimental). Requires laws=true.")),
                ("runHeavyAfterQuicktest", SBool("Run Shadow Heavy after each script/quicktest")),
                ("serendipityTimer", SBool("Run Shadow Heavy once when enabled, then on an interval while Trowser runs")),
                ("serendipityIntervalSeconds", SInt("Serendipity interval seconds (default 300)")),
                ("disabledLaws", SArr("Law ids to mute (same as UI checkbox beside each Law)")),
                ("activeLawSources", SArr("Law source file keys to run in Shadow (embedded:… or full user path). Omit to leave unchanged; null clears explicit selection so all loaded files run."))
            )),

        Tool("browser_shadow_check",
            "Run Shadow Heavy now on the current page: every loaded Law (page/response/console/heavy triggers) plus heavy quicktests from Shadow config. " +
            "Requires Shadow enabled with laws=true. Returns SummaryLine and non-pass Law lines. " +
            "Playbook: browser_security_shadow enabled=true laws=true → browser_navigate → browser_shadow_check. " +
            "Light checks run automatically after navigation; use browser_laws action check for page Laws only without Heavy cost. REST: POST /api/shadow/check.",
            Schema()),

        Tool("browser_laws",
            "Declare and manage Trowser Laws (.csx invariants: Site/Law/OnPage/Expect). Laws are read-only checks — no Navigate/Click/Fetch. " +
            "Embedded Laws ship with Trowser; user Laws live under Documents/Trowser Quicktests/Laws/. " +
            "Playbook for a new invariant: (1) action validate or author with natural language, (2) action add with compilable code (no await CheckLaws — that is Script Console only), " +
            "(3) browser_security_shadow laws=true, (4) browser_navigate target, (5) action check or browser_shadow_check. " +
            "Script one-offs: browser_run_script with Law(...) then await CheckLaws() (script scope) or CheckLaws(allLoaded: true). " +
            "See browser_scripting_help topic=laws. REST: GET /api/laws, POST /api/laws/validate|add|author, GET/POST /api/laws/proposals/*.",
            Schema(
                ("action", SStr("list (default), check, proposals, validate, author, accept, reject, add, replace, delete")),
                ("code", SStr("Law C# source for validate, add, or replace")),
                ("text", SStr("Natural language for author")),
                ("id", SStr("Proposal id for accept/reject")),
                ("fileName", SStr("Target .csx for add/replace/delete (default custom.csx)")),
                ("path", SStr("For delete: full path to user Law file (alternative to fileName)")),
                ("nameFilter", SStr("For check: substring filter on Law name")),
                ("allLoaded", SBool("For check: true = embedded+user Laws (default); false = Laws declared in current script run only")),
                ("includeTraffic", SBool("For check: replay session network + console buffers through response/console Laws (default false)"))
            )),

        Tool("browser_firewall_test",
            "Live-verify client defenses (CSP, SRI, iframe sandbox, Permissions-Policy) by injecting bypass techniques — not static header analysis. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("tests", SArr("Which defenses to test: 'all' (default), 'csp', 'sri', 'sandbox', 'permissions-policy'")),
                ("probes", SArr("CSP probes to run. Omit for the default in-page set (inline script, eval, event handler, nonce, base-uri, data: script, blob: script). Name javascript-url, form-action, frame-src, or worker-blob to add those. An explicit list replaces the default CSP set and does not change sri/sandbox/permissions-policy.")),
                ("verbose", SBool("When true, full per-defense findings and tests (long evidence). When false, compact results[] and summary only"))
            )),

        Tool("browser_client_surface",
            "Client-side attack-surface map: sources, sinks, message listeners, tabnabbing links, clobber candidates, service workers/caches, " +
            "source×sink cells, and a risks checklist (dismiss / lead / pursue / manual) for browser-side bug classes. " +
            "Clues only — does not run XS-Leaks, gadget chains, or the postMessage audit. nextActions are the pursue and lead follow-ups. " +
            "Installs the runtime sensor when needed. Prefer after browsing key flows. REST: POST /api/security/client-surface.",
            Schema(
                ("installSensor", SBool("Install the shared runtime sensor if not already present (default: true)")),
                ("waitMs", SInt("Settle wait before reading the event log (default: 400)")),
                ("reloadForSensor", SBool("Reload once after installing the sensor so page scripts run under hooks (default: true)")),
                ("reset", SBool("Clear runtime sensor buffer for this document scope before mapping (default: false)")),
                ("scopeToCurrentDocument", SBool("When false, include session history from earlier navigations on the origin (default: true)"))
            )),

        Tool("browser_security_service_worker_audit",
            "Structured service worker audit on the current origin: registrations, controlling worker, Cache Storage names, " +
            "optional in-page fetch of worker scripts (importScripts, fetch handler, cache.put, clients.claim heuristics), " +
            "scope-boundary hints, and document Trusted Types posture from response headers. Requires safetyMode: safe or higher.",
            Schema(
                ("safetyMode", SStr("Safety mode: safe (default) | active | aggressive")),
                ("fetchScripts", SBool("Fetch worker script bodies via in-page fetch for static analysis (default: true)")),
                ("maxScriptBytes", SInt("Max bytes per worker script when fetchScripts is true (default: 256000, max: 512000)"))
            )),

        Tool("browser_security_xssi_scan",
            "Cross-Site Script Inclusion (XSSI) / JSONP assessment: re-GETs script/JSON URLs from the network log (or explicit urls[]) " +
            "with session cookies and flags JSON arrays without nosniff, JavaScript array/assignment bodies, and callback/JSONP wrappers. " +
            "Hygiene-tier leads — confirm with a cross-origin script include. Follow-up when client-surface XSSI row is lead. " +
            "REST: POST /api/security/xssi-scan. Requires safetyMode: safe or higher.",
            Schema(
                ("safetyMode", SStr("Safety mode: safe (default) | active | aggressive")),
                ("urls", SArr("Optional explicit absolute URLs to probe (skips log discovery when set)")),
                ("maxUrls", SInt("Max URLs to probe from log or urls[] (default 12, max 30)")),
                ("timeoutMs", SInt("Per-URL GET timeout ms (default 12000)")),
                ("includeNetworkLog", SBool("Discover candidates from session network log when urls omitted (default true)"))
            )),

        Tool("browser_postmessage_audit",
            "Enumerate postMessage listeners, grade origin checks (none/weak/strict), screen with synthetic MessageEvents " +
            "(never filing-grade critical), and confirm with mocked attacker-origin technique probes at active. " +
            "Returns techniques, posture, coverage + nextActions. suggestOnly for recon after browse. " +
            "REST: POST /api/security/postmessage. Requires safetyMode: safe or higher.",
            Schema(
                ("safetyMode", SStr("Safety mode: safe (default, synthetic fuzz) | active | aggressive (attacker-origin proof)")),
                ("fuzz", SBool("Dispatch synthetic MessageEvents (default: true)")),
                ("maxPayloads", SInt("Max fuzz payloads (default: 8, max: 20)")),
                ("maxPayloadsPerListener", SInt("Schema payloads per listener for active proof (default: 2)")),
                ("depth", SStr("quick (default, child-iframe only) | deep (popup/framed topologies)")),
                ("suggestOnly", SBool("Listeners + schemas only, no fuzz (default: false)")),
                ("includeOutbound", SBool("Correlate outbound postMessage/window.name from session log (default: true)")),
                ("includeHistory", SBool("Include listeners from session history, not only current document (default: false)")),
                ("reset", SBool("Clear runtime listener log before enumerate (default: false)")),
                ("descendIframes", SBool("When top document has no listeners, walk same-origin iframe src URLs (default: true)")),
                ("attackerOrigin", SStr("Override mocked attacker origin for active proof (e.g. sibling host experiments)")),
                ("maxSeconds", SInt("Wall-clock budget; 0 = none")),
                ("listenerFilter", SStr("Substring match on listenerId or handler preview")),
                ("topologies", SArr("Technique ids: child-iframe, popup-to-opener, framed-target, child-frame-target, opener-to-popup (aggressive)"))
            )),

        Tool("browser_security_client_prototype_pollution",
            "Client-side prototype pollution via URL query/hash and postMessage canaries, then optional gadget→sink escalation. " +
            "Separate from server-side prototype_pollution_scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("baseUrl", SStr("Base URL to probe (default: current page)")),
                ("tryGadgets", SBool("After pollution, try a small gadget table toward sinks (default: true)"))
            )),

        Tool("browser_dom_flows",
            "Show every point where attacker-controlled data becomes executable or security-sensitive DOM state. " +
            "Builds source→JS→mutation→sink→consequence chains from the runtime sensor. " +
            "mode=observe (passive) or mode=probe (plants canaries; requires safetyMode:active).",
            Schema(
                ("mode", SStr("observe (default) | probe")),
                ("safetyMode", SStr("Required for probe: active | aggressive")),
                ("waitMs", SInt("Settle wait for observe mode (default: 400)")),
                ("waitForSpa", SBool("Wait for idle + SPA roots after observe/probe navigations (default: true)")),
                ("minTier", SStr("Filter chains: noise | hygiene (default) | probe-artifact | exploitable")),
                ("restoreUrl", SBool("After probe, restore pre-probe URL and probe localStorage keys (default: true)")),
                ("reset", SBool("Clear runtime sensor event buffer before observe/probe (default: false)")),
                ("sources", SArr("Optional probe sources: url-query, url-hash, storage, window-name, post-message, indexeddb")),
                ("canary", SStr("Optional canary string for probe mode"))
            )),

        Tool("browser_dom_xss_audit",
            "Active DOM XSS on the **current page** URL. Default depth=standard (medium): passive XSS + dom-flow probe + " +
            "trace-input on url-hash and single url-query key — not a full query sweep. Response includes applied{} showing what ran. " +
            "Use depth:deep for client-surface + probeAllUrlParams + script-gated traces. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("depth", SStr("quick | standard (default) | deep — controls default phases when flags omitted")),
                ("confirmExecution", SBool("Phase-2 __trowser_exec oracle (default: false; true when aggressive or depth:deep)")),
                ("runClientSurface", SBool("Client-surface map (default: false standard, true deep)")),
                ("runPassiveXss", SBool("Passive DOM XSS patterns (default: true)")),
                ("runDomFlowProbe", SBool("Active dom-flow canary probe (default: true)")),
                ("runTraceInput", SBool("trace-input legs (default: true standard/deep, false quick)")),
                ("probeAllUrlParams", SBool("Sweep all query keys (default: false standard, true deep)")),
                ("probeUrlHash", SBool("Full-fragment hash trace (default: true standard/deep)")),
                ("runScriptGatedTraces", SBool("Extra traces from inline script hints (default: false standard, true deep)")),
                ("fireEvents", SBool("Click first same-page anchor after navigation (default: false)")),
                ("timeoutMs", SInt("Per nested trace-input wait ms (default: 6000 standard)")),
                ("maxSeconds", SInt("Orchestrator wall clock (default: 45 standard, 90 deep; REST: budget.maxSeconds)"))
            )),

        Tool("browser_security_gadget_chains",
            "Client-side gadget chain orchestrator: ranks runtime gadget-read/proto-read events, then runs tailored " +
            "clobber, client prototype pollution, and dom-flow probes with confirmation. Requires safetyMode:active.",
            Schema(
                ("safetyMode", SStr("active (required) | aggressive")),
                ("probes", SArr("Optional subset: clobber, client-pp, dom-flow-probe")),
                ("maxSeconds", SInt("Wall-clock budget (0 = no limit)")),
                ("includeRadar", SBool("Ensure gadget radar is running before scan (default true)")),
                ("targetGlobals", SArr("Override global names for clobber probes")),
                ("perturbingRadar", SBool("Install Object.prototype getter traps during scan (explicit session only)")),
                ("includeHygiene", SBool("Include hygiene-tier findings in response (default true)"))
            )),

        Tool("browser_gadget_radar",
            "Runtime gadget radar: missing-global reads (Shadow-safe) and optional perturbing proto-read traps. " +
            "action=start|stop|read (default read). Perturbing start requires safetyMode:active.",
            Schema(
                ("action", SStr("read (default) | start | stop")),
                ("perturbing", SBool("When action=start, install Object.prototype getter traps (default false)")),
                ("protoKeys", SArr("Optional keys for perturbing proto traps")),
                ("safetyMode", SStr("Required for perturbing start: active"))
            )),

        Tool("browser_security_xs_leaks",
            "Cross-site leak differential scanner: attacker context (iframe/popup/resource) measures observables " +
            "across two victim states and asks whether an attacker can distinguish them. " +
            "Requires safetyMode safe+; active enables popups and higher-trial timing. Uses mocks (blocked in --safe).",
            Schema(
                ("safetyMode", SStr("safe (default techniques) | active (popups + timing) | aggressive")),
                ("states", SArr("Optional victim states [{label,url,identity?,setupUrl?,role?}]. When omitted or fewer than two, states are auto-derived (default).")),
                ("hypothesis", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional secret under test: { secret, kind?, urlTemplate?, hitValues?, missValues? }",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["secret"] = SStr("Human-readable secret being tested"),
                        ["kind"] = SStr("value | login-state | cross-user | diagnosis"),
                        ["method"] = SStr("GET (default) or POST"),
                        ["urlTemplate"] = SStr("URL with {value} placeholder (URL-encoded per value)"),
                        ["formFields"] = new Dictionary<string, object> { ["type"] = "object", ["description"] = "POST fields; values may contain {value}" },
                        ["hitValues"] = SArr("Values that should satisfy the secret"),
                        ["missValues"] = SArr("Values that should not")
                    }
                }),
                ("suggestOnly", SBool("Return candidate hypotheses without running probes")),
                ("autoStates", SBool("Derive states from identities, search traffic, or protected URLs. Defaults to true when states are omitted; set false to require explicit states.")),
                ("attackerSite", SStr("Attacker fixture: cross-site (default, evil.trowser.test) or same-site (evil-samesite.{victimHost})")),
                ("techniques", SArr("Optional technique/category filter: iframe-load, script-error, fetch-redirect-type, ...")),
                ("trials", SInt("Override trials per technique (default varies by technique)")),
                ("skipWarmup", SBool("Skip warm-up trial round (default false)")),
                ("includePosture", SBool("Run isolation posture analyzer (default true). Set false for oracle-only scans.")),
                ("postureInteractionProbes", SBool("Active COOP opener + Fetch Metadata enforcement probes (default: on in active mode only).")),
                ("fullCatalog", SBool("Run entire technique catalog (slow on WAN; default false)")),
                ("maxSeconds", SInt("Wall-clock budget (0 = none). REST alias for budget.maxSeconds.")),
                ("observeMode", SBool("Record observables without filing-grade differentials (default false)")),
                ("identifyAuthCookie", SBool("Label which cookie drives credentialed state pairs (default false)"))
            )),

        Tool("browser_trace_input",
            "Trace payload causality from injection source through network (if any) into the DOM. " +
            "Sources: form, url-query, url-hash, url-path, window-name, storage, post-message, referrer. " +
            "Detects input filtering vs encoding, server reflection, DOM rendering context, CSP, and sink reachability (canary taint). " +
            "When a form control filters input, automatically probes URL query/hash vectors (probeUrlSources, default true). " +
            "autoBypass tries alternative XSS payloads; monitorSinks installs the shared runtime sensor (eval/innerHTML/location/fetch/…). " +
            "Always returns instrumented sink inventory + sinksSeen even when hitCount is 0. Requires safetyMode: active.",
            Schema(
                ("source", SStr("Injection source: form (default), url-query, url-hash, url-path, window-name, storage, post-message, referrer")),
                ("target", SStr("CSS selector for input element (required when source=form)")),
                ("baseUrl", SStr("Base URL for url-* / referrer sources (default: current page URL)")),
                ("queryParam", SStr("Query parameter name for url-query (default: q)")),
                ("hashParam", SStr("Hash parameter name for url-hash — omit to use payload as entire fragment")),
                ("storageKey", SStr("Storage key for source=storage (default: trowser_probe)")),
                ("storageKind", SStr("local (default) or session for source=storage")),
                ("queryEncode", SStr("Query encoding: none (default for DOM XSS), component, form")),
                ("fragmentEncode", SStr("Fragment encoding: none (default for DOM XSS), component, form")),
                ("pathEncode", SStr("Path segment encoding for url-path (default: component)")),
                ("probeUrlSources", SBool("After form filtering, auto-probe url-query and url-hash (default: true)")),
                ("payload", SStr("Single payload (default with autoBypass: <script>alert(1)</script>)")),
                ("payloads", SArr("Batch payloads (not compatible with autoBypass)")),
                ("submit", SStr("CSS selector for submit button")),
                ("submitAction", SStr("click (default), enter, none")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("autoBypass", SBool("Try alternative XSS vectors when primary fails (default: true)")),
                ("maxBypassAttempts", SInt("Max alternative vectors (default: 10, max: 15)")),
                ("checkCsp", SBool("Evaluate CSP blocking (default: true)")),
                ("timeout", SInt("Max wait ms (default: 10000)")),
                ("detectSqli", SBool("Scan response bodies for SQL error signatures")),
                ("monitorSinks", SBool("Hook dangerous JS sinks and report payload reachability (default: true)")),
                ("twoPhase", SBool("Phase-1 reach canary then context-aware confirmation payload (default: true)")),
                ("probeAllUrlParams", SBool("For url-query: inject reach canary into every discovered query parameter")),
                ("fireEvents", SBool("After navigation, click first same-page anchor (window.open / click-gated flows)")),
                ("confirmExecution", SBool("Phase-2 __trowser_exec oracle (default: true only when safetyMode is aggressive)"))
            )),

        Tool("browser_security_sqli_scan",
            "SQL injection probe with unified findings (id/category/severity/confidence/tier/endpoint/param/payload/evidence/proofHint/nextActions). " +
            "Substitutes payloads at §marker§ / {{marker}}, uses noise-stripped boolean differentials, optional UNION column ladder (depth=deep), " +
            "and multi-sample time delays when enabled. depth: quick|standard|deep. " +
            "Default response filters tier=exploitable and confidence≥likely (override with includeHygiene / minConfidence). " +
            "Shorthand: { url, param }. REST: POST /api/security/sqli-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("Shorthand absolute URL (use with param)")),
                ("param", SStr("Shorthand query parameter name to inject (alias: paramName)")),
                ("paramName", SStr("Alias for param")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "{ url, method?, headers?, body?|json? } — must include one injection marker",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL template with §id§ or {{id}}"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Body template with markers"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("depth", SStr("Scan breadth: quick | standard (default) | deep")),
                ("baselineValue", SStr("Safe substitution for baseline request (default: 1)")),
                ("includeTimeBased", SBool("Add SLEEP/WAITFOR payloads (default: false; deep enables by default)")),
                ("payloads", SArr("Optional custom payload strings (replaces built-in set)")),
                ("timeoutMs", SInt("Per-request timeout (default: 15000)")),
                ("maxResponseBodyChars", SInt("Max chars scanned for SQL signatures per response (default: 131072)")),
                ("useBackendFetch", SBool("Use server HttpClient instead of browser fetch (avoids Zone.js; default false)")),
                ("includeBrowserCookies", SBool("With useBackendFetch: add WebView Cookie header per URL (default false)")),
                ("includeOrmClosurePayloads", SBool("Append ORM-style closure payloads (default false; deep enables)")),
                ("minConfidence", SStr("Minimum confidence to return: tentative | likely (default) | confirmed")),
                ("includeHygiene", SBool("Include hygiene/informational tiers (default false)"))
            )),

        Tool("browser_security_sqli_login_sweep",
            "SQL injection login bypass sweep: POST form+json on common login paths with tautology payloads. " +
            "Detects session cookie minting, redirect to authed page, logged-in markers, JSON token emergence. " +
            "REST: POST /api/security/sqli-login-sweep. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxLoginUrls", SInt("Max login URLs to probe (default 12)")),
                ("includeScaffold", SBool("Include built-in login paths when not in network log (default true)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("loginUrls", SArr("Optional explicit login URL list")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_nosql_scan",
            "NoSQL injection scan: operator payloads on query strings and JSON login/search endpoints. " +
            "Uses network log + ALWAYS_PROBED scaffold when traffic is sparse. REST: POST /api/security/nosql-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max injection points (default 10)")),
                ("includeScaffold", SBool("Probe built-in login/search templates when sparse (default true)")),
                ("sparseThreshold", SInt("API-like endpoint count below which scaffold runs (default 3)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_ldap_scan",
            "LDAP filter injection on login endpoints: baseline 401/403 then filter break-out payload. " +
            "REST: POST /api/security/ldap-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max login URLs (default 10)")),
                ("includeScaffold", SBool("Include built-in login paths (default true)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("loginUrls", SArr("Optional explicit login URL list")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_ssti_scan",
            "SSTI scan with unified findings. Discovers injectable parameters from network log or probes explicit request template. " +
            "Requires dual arithmetic confirm (49 and 56) for critical/confirmed; depth=deep adds a safe engine canary. " +
            "REST: POST /api/security/ssti-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional { url, method?, headers?, body?|json? } with §INJECT§ marker",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL template with §INJECT§ or {{INJECT}}"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Body template with markers"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("paramName", SStr("Parameter name for explicit template mode")),
                ("depth", SStr("Scan breadth: quick | standard (default) | deep")),
                ("maxCandidates", SInt("Max network-log candidates (default from depth)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("minConfidence", SStr("Minimum confidence to return: tentative | likely (default) | confirmed")),
                ("includeHygiene", SBool("Include hygiene/informational tiers (default false)"))
            )),

        Tool("browser_security_ssti_polyglot_scan",
            "Fast reflected SSTI probe: single GET polyglot payload (${7*7}{{7*7}}<%=7*7%>#{7*7}) across common search/render paths. " +
            "REST: POST /api/security/ssti-polyglot-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max paths to try (default 8)")),
                ("maxProbes", SInt("Max path×param probes; each probe = 2 GETs (default 48; 0 = unlimited)")),
                ("maxParams", SInt("Max query param names per path (0 = all defaults)")),
                ("timeoutMs", SInt("Per-request timeout (default 12000)")),
                ("includeScaffold", SBool("Include built-in paths (default true)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("paths", SArr("Optional path list (e.g. /search)")),
                ("params", SArr("Optional query parameter names"))
            )),

        Tool("browser_security_ssti_stored_scan",
            "Stored SSTI: POST template payload to profile fields, GET readback for 13289 marker (137*97). " +
            "REST: POST /api/security/ssti-stored-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max profile URL candidates (default 10)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("includeScaffold", SBool("Include built-in profile paths (default true)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("profileUrls", SArr("Optional explicit profile POST URLs"))
            )),

        Tool("browser_security_prototype_pollution_scan",
            "Server-side prototype pollution: POST __proto__/constructor.prototype payload, GET verify canary echo. " +
            "REST: POST /api/security/prototype-pollution-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max JSON sink URLs (default 10)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("includeScaffold", SBool("Include built-in JSON paths (default true)")),
                ("includeBrowserCookies", SBool("Merge WebView cookies (default true)")),
                ("candidateUrls", SArr("Optional explicit POST URLs"))
            )),

        Tool("browser_security_supply_chain_scan",
            "Supply chain scan: Retire.js CVEs, third-party/SRI inventory, manifest fetch + OSV.dev advisory lookup, " +
            "CI/CD pipeline exposure (.github/workflows, Jenkinsfile, .gitlab-ci.yml), JS bundle dependency fingerprinting, " +
            "Retire+OSV cross-check, optional CVE reachability PoCs (Juice Shop deps). " +
            "REST: POST /api/security/supply-chain-scan. Set safetyMode: active for CVE reachability and full manifest OSV pass.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required for CVE reachability) | aggressive. Default: safe")),
                ("includeManifestFetch", SBool("Fetch package.json/lockfiles (default true)")),
                ("includeCiCdProbe", SBool("Probe CI/CD config paths (default true)")),
                ("includeBundleDeps", SBool("Fingerprint npm packages from JS bundles/source maps (default true)")),
                ("includeSourceMaps", SBool("Parse source maps for node_modules paths (default true)")),
                ("includePathFilterBypass", SBool("Try /ftp/ NUL bypass for manifests (default true)")),
                ("includeCveReachability", SBool("Run CVE exploit primitives (requires safetyMode: active)")),
                ("includeRetireOsvCrossCheck", SBool("OSV lookup for tech-stack/manifest/bundle deps missed by Retire (default true)")),
                ("maxOsvPackages", SInt("Cap OSV batch size (default 200)")),
                ("maxBundleScripts", SInt("Max script[src] bundles to scan (default 24)")),
                ("timeoutMs", SInt("HTTP timeout ms (default 30000)"))
            )),

        Tool("browser_security_osv_check",
            "OSV.dev enrichment for a raw manifest body without web fetch — useful for testing manifest parsers and advisory lookup offline. " +
            "Accepts package.json, lockfiles, requirements.txt, pyproject.toml, composer.json, yarn.lock. " +
            "REST: POST /api/security/osv-check.",
            Schema(
                ("manifest", SStr("Raw manifest body (required)")),
                ("fileName", SStr("Manifest filename for parser selection (default package.json)")),
                ("ecosystem", SStr("Optional ecosystem override: npm, PyPI, Packagist, Maven, etc.")),
                ("maxPackages", SInt("Cap OSV batch size (default 200)"))
            )),

        Tool("browser_security_csti_scan",
            "Client-side template injection (CSTI) scan: navigates with template payloads and checks rendered DOM for arithmetic evaluation (49 from {{7*7}}). " +
            "Discovers URL query/hash parameters from DOM scripts and network log; prioritizes engines from tech stack (AngularJS, Vue, Handlebars). " +
            "REST: POST /api/security/csti-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("Explicit base URL (optional — default current page)")),
                ("paramName", SStr("Parameter name when url is set, or to limit discovery")),
                ("engines", SArr("Optional engine filter: angularjs, vue, handlebars, generic")),
                ("sources", SArr("Optional sources: url-query, url-hash (default both)")),
                ("escalate", SBool("Try sandbox-escape probes after basic confirmation (default false)")),
                ("monitorSinks", SBool("Hook dangerous JS sinks during probes (default true)")),
                ("maxCandidates", SInt("Max parameter candidates (default 10)")),
                ("timeoutMs", SInt("Per-navigation wait timeout (default 10000)"))
            )),

        Tool("browser_security_xss_scan",
            "Active XSS scan with unified findings. Reflected path uses char-survival fingerprint + context-driven payloads; " +
            "standard/deep DOM-verifies reflected hits via sink/CSP oracles. DOM probes use auto-bypass. " +
            "REST: POST /api/security/xss-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("Explicit base URL (optional — default current page)")),
                ("paramName", SStr("Parameter name when url is set")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional explicit request template with §marker§ or {{marker}} injection point",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL template with marker"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Body template with marker"),
                        ["json"] = new Dictionary<string, object> { ["description"] = "JSON body template" }
                    }
                }),
                ("depth", SStr("Scan breadth: quick | standard (default) | deep")),
                ("payloadProfile", SStr("Payload corpus breadth: small (default, built-in) | big (extended corpora subsets)")),
                ("includeReflected", SBool("Run reflected XSS probes via fetch (default true)")),
                ("includeDom", SBool("Run DOM XSS probes via navigation (default true)")),
                ("includeStored", SBool("Run stored XSS POST+readback probes (default false; deep enables)")),
                ("maxCandidates", SInt("Max parameter candidates (default from depth)")),
                ("maxBypassAttempts", SInt("Max auto-bypass payload variants per DOM candidate (default from depth)")),
                ("timeoutMs", SInt("Per-probe timeout (default 10000)")),
                ("minConfidence", SStr("Minimum confidence to return: tentative | likely (default) | confirmed")),
                ("includeHygiene", SBool("Include hygiene/informational tiers (default false)"))
            )),

        Tool("browser_security_parser_probe",
            "Parser differential probe: tests JSON POST/PUT/PATCH endpoints with Content-Type matrix (XML, form, multipart, java-serialized) " +
            "and body-shape variants (duplicate keys, type confusion, json-breaking). Flags content-type-confusion, deserialization-suspected, parser-differential. " +
            "REST: POST /api/security/parser-probe. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional explicit endpoint — otherwise discovers JSON POST/PUT/PATCH from network log",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("Endpoint URL"),
                        ["method"] = SStr("HTTP method (default POST)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("JSON body"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("maxCandidates", SInt("Max JSON endpoints to probe (default 5)")),
                ("includeContentTypeMatrix", SBool("Run Content-Type swap probes (default true)")),
                ("includeBodyShapeMatrix", SBool("Run body-shape probes (default true)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_deserialization_scan",
            "Deserialization scan: node-serialize `_$$ND_FUNC$$_` timing, YAML billion-laughs DoS, Java magic-byte and PHP unserialize stubs on JSON sinks. " +
            "REST: POST /api/security/deserialization-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max sink endpoints (default 8)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("includeJavaStub", SBool("POST application/x-java-serialized-object (default true)")),
                ("includePhpStub", SBool("POST PHP O:8 stdClass in JSON (default true)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)"))
            )),

        Tool("browser_security_file_upload_scan",
            "File upload validation: baseline PDF, 200KB oversize, .exe wrong-type, JPEG/PHP polyglot; optional upload XXE (multipart + raw XML). " +
            "REST: POST /api/security/file-upload-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max upload endpoints (default 10)")),
                ("timeoutMs", SInt("Per-request timeout (default 12000)")),
                ("includeXxe", SBool("Run upload XXE probes (default true)")),
                ("tryDomReplayWhenSpaShell", SBool("Hint browser_upload when SPA shell dedup triggers")),
                ("urls", SArr("Optional explicit upload URLs")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)"))
            )),

        Tool("browser_security_nextjs_rsc_scan",
            "Next.js RSC / Flight deserialization probe (CVE-2025-66478 class): fingerprint App Router, enumerate action hashes, send Flight canary payloads. " +
            "REST: POST /api/security/nextjs-rsc-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("timeoutMs", SInt("Per-request timeout (default 6000)")),
                ("requireNextJsFingerprint", SBool("Skip when Next.js not detected (default true)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)"))
            )),

        Tool("browser_security_race_condition_scan",
            "Race-condition / TOCTOU scan: discover single-use POST endpoints from traffic, fire concurrent identical POST bursts, flag when multiple 2xx accepted. " +
            "REST: POST /api/security/race-condition-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max endpoints to burst (default 8)")),
                ("burstSize", SInt("Concurrent requests per burst minus one (default 15 → 16 total)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 8000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("includeRedeemCodeBursts", SBool("Also burst endpoints with code/coupon/voucher body fields (default true)")),
                ("urls", SArr("Optional explicit POST URLs to burst"))
            )),

        Tool("browser_race_lab_profiles",
            "Race Lab profile presets: list/save/export/import multi-session race profiles (Hammer/Spike/Sequential/Random parameter presets). REST: GET/POST /api/race-lab/profiles, export/import.",
            Schema(
                ("mode", SStr("list (default) | save | export | import")),
                ("name", SStr("Profile name for save")),
                ("profile", SObj("Full profile object for save/run")),
                ("names", SArr("Profile names to export")),
                ("json", SStr("Export JSON for import mode"))
            )),

        Tool("browser_race_lab_synchronize",
            "Race Lab latency compensation: measure per-session RTT and compute dispatch offsets before a burst. REST: POST /api/race-lab/synchronize.",
            Schema(
                ("profile", SObj("Profile with requests[] to synchronize")),
                ("requests", SArr("Request list when profile omitted")),
                ("ensurePeerOrigin", SBool("Navigate peers to target origin first (default true)"))
            )),

        Tool("browser_race_lab_baseline",
            "Race Lab baseline pass: fire each configured request once sequentially. REST: POST /api/race-lab/baseline.",
            Schema(
                ("profile", SObj("Profile with requests[]")),
                ("requests", SArr("Request list when profile omitted"))
            )),

        Tool("browser_race_lab_run",
            "Race Lab run: sync (optional) → baseline (optional) → configurable burst (Hammer/Spike/Sequential/Random presets). Multi-session duplicate-action, competing-action, and TOCTOU checks. " +
            "Identical mutate bodies are suppressed unless side-effect ids differ (order/charge/booking ids, Location) or a check-role readback lists more of those ids than the baseline. Request ids and timestamps are ignored. " +
            "Timeline entries include identityUsed and cookiesSent. REST: POST /api/race-lab/run. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("profile", SObj("Profile: name, requests[], parameters")),
                ("runSync", SBool("Run latency compensation first (default true)")),
                ("runBaseline", SBool("Run soft baseline first (default true)")),
                ("ensurePeerOrigin", SBool("Navigate peers to origin before fetch (default true)")),
                ("minConfidence", SStr("Filter findings: tentative | likely | confirmed (default likely)")),
                ("includeHygiene", SBool("Include hygiene-tier findings (default false)"))
            )),

        Tool("browser_security_captcha_replay_scan",
            "CAPTCHA / challenge replay: fetch captcha credentials, submit twice to gated endpoints with same token; flags broken single-use anti-automation. " +
            "REST: POST /api/security/captcha-replay-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxSubmitCandidates", SInt("Max submit endpoints (default 6)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 8000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)"))
            )),

        Tool("browser_security_llm_redteam_scan",
            "OWASP LLM Top 10 app-layer red-team scan (YAML corpus + optional RAG/peer/consumption/WebMCP). HTTP adapter or chat UI. " +
            "REST: POST /api/security/llm-redteam-scan. Requires safetyMode: active. See properties for mode/target knobs.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("mode", SStr("auto | http | api | chat | ui. http/api never fall back to chat-UI (default auto)")),
                ("preset", SStr("Optional: smoke = HTTP-only, ≤8 probes (good DIY warm-up)")),
                ("maxProbes", SInt("Max corpus probes to run (default 28; 0 = adjacent scanners only)")),
                ("concurrency", SInt("Parallel probes — HTTP mode only; chat-ui always sequential (default 2)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 30000)")),
                ("probeDelayMs", SInt("Delay between probes in chat-ui mode, 200-10000ms (default 1000)")),
                ("includeWebMcpAbuse", SBool("Run WebMCP tool abuse catalog after probes (default true)")),
                ("includeIndirectInjection", SBool("Upload doc with hidden instruction + summarize (default false)")),
                ("includeRagPoison", SBool("LLM04/08 RAG/memory poison + optional peer isolation (default false)")),
                ("includeUnboundedConsumption", SBool("LLM10 flood/oversized/max-output/tool-loop (default false)")),
                ("probeAnonymousAccess", SBool("Retry best chat POST without cookies (anon vs session assist)")),
                ("peerBaseUrl", SStr("Optional peer Trowser base URL for LLM08 cross-tenant check")),
                ("peerApiKey", SStr("Bearer API key for peerBaseUrl")),
                ("registerWhisperHints", SBool("Push findings to Red Team Whisper (default true)")),
                ("probeIds", SArr("Optional probe id filter")),
                ("categories", SArr("Optional OWASP LLM category filter")),
                ("httpTarget", new Dictionary<string, object> { ["type"] = "object", ["description"] = "{ url, schema, model, headers, useBackendFetch, customBody (object, array, or form/raw string with {{PROMPT}}), customResponseKey }" }),
                ("chatTarget", new Dictionary<string, object> { ["type"] = "object", ["description"] = "{ inputSelector, submitSelector, responseSelector, waitAfterSubmitMs } — responseSelector gets highest priority in capture" })
            )),

        Tool("browser_security_llm_redteam_probes",
            "List LLM red-team probe catalog: probe IDs, categories, coverage metadata (covered vs notCoveredInCorpus). " +
            "Gate-free. REST: GET /api/security/llm-redteam-probes.",
            Schema()),

        Tool("browser_security_llm_endpoint_discover",
            "Discover LLM/chat integration: network log chat/completion APIs (including SSE text/event-stream and form-urlencoded prompt fields), WebSocket connections (JSON chat message pattern analysis), " +
            "DOM chat widgets (including off-screen inputs), WebMCP tools, copilot iframes. Warns when reCAPTCHA/hCaptcha/Turnstile bot gates are present. " +
            "WebSocket endpoints appear with source 'websocket', method 'WS'. " +
            "Updates Red Team Whisper surface summary. REST: GET or POST /api/security/llm-endpoint-discover.",
            Schema()),

        Tool("browser_security_llm_chat_interact",
            "Send one prompt through the page chat UI and return responseText/responseHtml. " +
            "Supports chatTarget.resetUi (reload chat before send) and failoverToHttp (default true) when Typing… sticks. " +
            "REST: POST /api/security/llm-chat-interact. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("prompt", SStr("Prompt text to send")),
                ("chatTarget", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Optional { inputSelector, submitSelector, responseSelector, waitAfterSubmitMs, resetUi, failoverToHttp }" }),
                ("resetUi", SBool("Reload current URL before send (clears stuck Typing… locks)"))
            )),

        Tool("browser_security_llm_http_send",
            "One-shot: send a prompt over a discovered (or explicit) LLM HTTP endpoint with inferred customBody. " +
            "Immune to chat UI Typing locks. Prefer this for DIY probing. REST: POST /api/security/llm-http-send. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: active required")),
                ("prompt", SStr("Prompt text")),
                ("httpTarget", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Optional { url, schema, customBody }. If omitted, uses suggestedHttpTarget from discovery." })
            )),

        Tool("browser_security_llm_http_mcp_list",
            "Discover/list tools on an HTTP JSON-RPC MCP endpoint (initialize → tools/list). " +
            "Distinct from in-page WebMCP. REST: POST /api/security/llm-http-mcp-list. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: active required")),
                ("url", SStr("Optional MCP URL; defaults to best discovered /mcp endpoint")),
                ("includeBrowserCookies", SBool("Include browser cookies (default true)"))
            )),

        Tool("browser_security_llm_sink_assist",
            "Assistive LLM→XSS path: instrument sinks, optional mock of chat API with canary HTML, return canaryExecuted. " +
            "Not auto-confirmed XSS — enough for a write-up. REST: POST /api/security/llm-sink-assist. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: active required")),
                ("mockChatApi", SBool("Mock discovered chat API with canary HTML (default false)")),
                ("chatApiUrl", SStr("Optional chat API URL to mock")),
                ("canary", SStr("Optional canary string")),
                ("maxProbes", SInt("Optional sink-trace probes (default 1)"))
            )),

        Tool("browser_security_rate_limit_audit",
            "Observational rate-limit audit (A12): discover login/search/OTP/write endpoints from traffic, run sequential baseline then small concurrent burst. " +
            "Emits missing-rate-limit, weak-rate-limit, or rate-limit-present. Honors 429/Retry-After when respectRateLimits is true (default). " +
            "REST: POST /api/security/rate-limit-audit. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max endpoints (default 8)")),
                ("sequentialAttempts", SInt("Sequential requests before burst (default 5, max 10)")),
                ("burstSize", SInt("Concurrent burst size (default 8, max 15)")),
                ("delayMs", SInt("Delay between sequential requests ms (default 200)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 8000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("respectRateLimits", SBool("Backoff on HTTP 429 with Retry-After (default true)")),
                ("includeOtpTemplates", SBool("Use wrong OTP payloads on OTP endpoints (default true, max 10 attempts)")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("urls", SArr("Optional explicit URLs to audit"))
            )),

        Tool("browser_security_redos_scan",
            "ReDoS timing oracle: single evil-regex payload per injectable search/filter/email parameter (max 3 payloads, sequential). " +
            "REST: POST /api/security/redos-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max injectable endpoints (default 8)")),
                ("maxPayloadsPerCandidate", SInt("Payloads per parameter (default 3, max 3)")),
                ("slowThresholdSeconds", SInt("Flag when attack exceeds this many seconds (default 3)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 8000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("respectRateLimits", SBool("Backoff on HTTP 429 (default true)")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("urls", SArr("Optional explicit URLs with injectable query params"))
            )),

        Tool("browser_security_body_size_limit_scan",
            "Body-size limit probe: escalating tiers 1 KB → 64 KB → 256 KB → 1 MB (one request per tier) on POST endpoints. " +
            "REST: POST /api/security/body-size-limit-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max POST endpoints (default 6)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 15000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("respectRateLimits", SBool("Backoff on HTTP 429 (default true)")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("urls", SArr("Optional explicit POST URLs"))
            )),

        Tool("browser_security_costly_operations",
            "Single-request cost risk scan from captured traffic and DOM: large responses, weak paging, heavy routes, bulk input, compose-links to graphql/LLM/SSRF probes. " +
            "REST: POST /api/security/costly-operations. Default safetyMode: passive (zero extra HTTP). Optional bounded confirms with safe/active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive (default) | safe | active | aggressive")),
                ("checks", SArr("Check ids to run; omit for all passive checks. Add confirm-page-size, confirm-image-edge, confirm-multi-id for bounded probes")),
                ("maxCandidates", SInt("Max endpoints per rule (default 24)")),
                ("timeoutMs", SInt("Per confirm request timeout ms (default 15000)")),
                ("maxResponseBytes", SInt("Abort confirm if response exceeds this size (default 2097152)")),
                ("slowThresholdMs", SInt("Flag slow sync calls above this ms (default 3000)")),
                ("includeSpaDom", SBool("Include file inputs from DOM (default true)")),
                ("includeBrowserCookies", SBool("Send session cookies on confirms (default true)")),
                ("respectRateLimits", SBool("Backoff on HTTP 429 (default true)")),
                ("registerChainFindings", SBool("Register observed/confirmed findings for chain-analyze (default true)")),
                ("urls", SArr("Optional URL scope filter")),
                ("includeSpecsFromNetwork", SBool("Analyze OpenAPI/GraphQL schema from captured responses (default true)")),
                ("specUrls", SArr("Optional explicit spec document URLs from the network log"))
            )),

        Tool("browser_security_swaggering",
            "Swaggering: discover OpenAPI/Swagger, inventory shadow APIs, and exercise documented operations with the browser session " +
            "(smoke, auth delta, forced errors, missing fields, cost edges, shadow paths, auto-scan on the catalog). Not a Postman replacement — uses your logged-in cookie jar. " +
            "Pass specUrls when the document is not already in the network log. Response includes operations[] (method, path, outcome, status) and finding evidence excerpts. " +
            "REST: POST /api/security/swaggering (alias openapi-smoke). Default depth thorough (~20 min budget). Requires safetyMode active for mutating probes.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (default) | aggressive")),
                ("depth", SStr("quick | standard | thorough (default)")),
                ("maxStepSeconds", SInt("Wall-clock budget override (default from depth; thorough ≈ 1200)")),
                ("specUrls", SArr("Optional explicit OpenAPI document URLs")),
                ("includeSpecsFromNetwork", SBool("Parse OpenAPI from captured responses (default true)")),
                ("includeOpenApiProbes", SBool("GET-probe well-known spec paths (default true)")),
                ("pathPrefix", SStr("Only operations under this path prefix")),
                ("includeDeleteMethods", SBool("Include DELETE operations (default false; use with aggressive)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("includeCostlySpecLimits", SBool("Passive spec cost hints (default true)"))
            )),

        Tool("browser_security_workflow_skip_scan",
            "Workflow step-skip: late-stage POST endpoints from traffic; captured-body replay → info observation; minimal {} → medium finding when not gated. " +
            "REST: POST /api/security/workflow-skip-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxCandidates", SInt("Max late-stage endpoints (default 8)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 10000)")),
                ("includeBrowserCookies", SBool("Send session cookies (default true)")),
                ("tryMinimalBody", SBool("Also try {} when captured body fails (default true)")),
                ("urls", SArr("Optional explicit POST URLs — bypass late-stage keyword filter"))
            )),

        Tool("browser_security_fail_open_scan",
            "Fail-open scan: replay traffic-derived sensitive endpoints without session cookies and with invalid JWT. " +
            "Categories: fail-open-unauthenticated, fail-open-invalid-token. " +
            "REST: POST /api/security/fail-open-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxEndpoints", SInt("Max endpoints to probe (default 10)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)")),
                ("includeUnauthenticated", SBool("Test cookie-stripped replay (default true)")),
                ("includeInvalidToken", SBool("Test invalid Bearer JWT (default true)")),
                ("includeAfterError", SBool("Deprecated no-op (simulated post-500 branch removed); accepted for compatibility")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("urls", SArr("Optional explicit URLs — bypass traffic discovery"))
            )),

        Tool("browser_security_auth_control_identifier",
            "Identify which cookies, headers, and token fields actually gate a request: baseline replay, then omit and one-character-tamper each candidate. " +
            "Verdicts: enforced, presence-only, ignored, value-checked-but-optional, inconclusive. " +
            "REST: POST /api/security/auth-control-identifier. Requires safetyMode: active. Prefer Endpoint Probe GUI for request selection.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("Single request URL (optional if endpoints[] or network log)")),
                ("method", SStr("HTTP method for single request (default GET)")),
                ("body", SStr("Request body for single request")),
                ("headers", SObj("Request headers object for single request")),
                ("endpoints", SArr("Array of {url, method?, headers?, body?} — preferred for multi-request")),
                ("allHeaders", SBool("Test every non-hop-by-hop header, not only auth/token-like names (default false)")),
                ("includeBodyFields", SBool("Include matching body fields (default true)")),
                ("includeQueryFields", SBool("Include matching query fields (default true)")),
                ("maxEndpoints", SInt("When falling back to network log, max endpoints (default 5)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)"))
            )),

        Tool("browser_security_missing_parameter_scan",
            "Missing-parameter scan: omit each top-level JSON field on traffic-derived POST bodies; flags 500+stack traces and NPE field hints. " +
            "REST: POST /api/security/missing-parameter-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxEndpoints", SInt("Max JSON POST endpoints (default 8)")),
                ("maxFieldsPerEndpoint", SInt("Max fields to omit per endpoint (default 8)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 12000)")),
                ("registerChainFindings", SBool("Register findings for chain-analyze (default true)")),
                ("urls", SArr("Optional explicit POST URLs"))
            )),

        Tool("browser_security_session_fixation_scan",
            "Detects session fixation — compares cookies before/after login (excludes CSRF/analytics; ignores stable cookies when a new session cookie is issued). " +
            "Uses browser DOM form submit first (CSRF/hidden fields/multi-step). " +
            "REST: POST /api/security/session-fixation-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("loginUrl", SStr("Optional login URL")),
                ("username", SStr("Optional username")),
                ("password", SStr("Optional password")),
                ("usernameField", SStr("Form username field name (e.g. uid)")),
                ("passwordField", SStr("Form password field name (e.g. passw)")),
                ("contentType", SStr("Login Content-Type (HTTP fallback only)")),
                ("body", SStr("Login body template with §USER§/§PASS§ placeholders (HTTP fallback)")),
                ("preferBrowserLogin", SBool("Use browser DOM login first (default true)")),
                ("cookieName", SStr("Optional session cookie name filter")),
                ("tryDefaultCredentials", SBool("Try built-in default creds when username omitted (default true)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 15000)"))
            )),

        Tool("browser_security_password_reset_weak_scan",
            "Weak password-reset via security questions — fetch question, try canonical answers. " +
            "REST: POST /api/security/password-reset-weak-scan. Requires safetyMode: active; confirmDestructive to change password.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("confirmDestructive", SBool("Attempt password change (default false)")),
                ("email", SStr("Target email")),
                ("questionUrl", SStr("Security question URL")),
                ("resetUrl", SStr("Password reset POST URL")),
                ("maxAttempts", SInt("Max canonical answers (default 12)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 15000)"))
            )),

        Tool("browser_security_account_enumeration_scan",
            "Account enumeration — REST user-list leak, login valid/invalid differential, registration duplicate email. " +
            "REST: POST /api/security/account-enumeration-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("loginUrl", SStr("Optional login URL")),
                ("validUsername", SStr("Known-valid username for differential probe")),
                ("registerUrl", SStr("Optional registration URL")),
                ("usernameField", SStr("Form username field name")),
                ("passwordField", SStr("Form password field name")),
                ("contentType", SStr("Login Content-Type")),
                ("body", SStr("Login body template with §USER§/§PASS§ placeholders")),
                ("includeRestLeak", SBool("Probe REST scaffold paths (default true)")),
                ("includeLoginDifferential", SBool("Compare valid vs invalid login responses (default true)")),
                ("includeRegisterProbe", SBool("Probe duplicate registration messages (default true)")),
                ("timeoutMs", SInt("Per-request timeout ms (default 15000)"))
            )),

        Tool("browser_security_logout_invalidation_probe",
            "Logout invalidation — replay protected endpoint with pre-logout cookie after logout. " +
            "REST: POST /api/security/logout-invalidation-probe. Requires safetyMode: active. Browse while logged in first.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("logoutUrl", SStr("Logout URL")),
                ("logoutMethod", SStr("Logout HTTP method (e.g. POST). Applied even when logoutUrl is discovered automatically")),
                ("logoutBody", SStr("Logout POST body (form-urlencoded or JSON)")),
                ("logoutContentType", SStr("Content-Type for logout POST")),
                ("protectedUrl", SStr("Protected resource URL to replay")),
                ("timeoutMs", SInt("Per-request timeout ms (default 15000)"))
            )),

        Tool("browser_security_cmd_canary",
            "Command injection canaries on injectable string parameters. " +
            "Tier A: shell output; Tier B: SSTI arithmetic; Tier D/E: browser callback (info) and confirmed timing. " +
            "REST: POST /api/security/cmd-canary. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional { url, method?, headers?, body?|json? } with §INJECT§ marker",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL template with §INJECT§ or {{INJECT}}"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Body template with markers"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("paramName", SStr("Parameter name for explicit template")),
                ("maxCandidates", SInt("Max injection points from network log (default 10)")),
                ("includeSstiTier", SBool("Include SSTI arithmetic tier (default true)")),
                ("includeCallback", SBool("Include OOB callback tier (default false)")),
                ("includeTiming", SBool("Include timing tier (default false)")),
                ("timingThresholdMs", SInt("Timing delta threshold ms (default 3500)")),
                ("callbackWaitMs", SInt("Wait after probes for callback hits (default 2000)")),
                ("callbackDomain", SStr("Custom callback domain")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_jwt_analyze",
            "Decode JWT-shaped tokens from document cookies (including HttpOnly cookies via the browser cookie jar), " +
            "localStorage, and sessionStorage; optional `token` / `tokens` in the " +
            "body decodes a JWT you already have (e.g. from fetch). Reports alg, exp, sensitive claims, algorithm-confusion reminders. " +
            "Does not forge tokens or send probes. REST: POST /api/security/jwt-analyze. Passive — no safetyMode required.",
            Schema(
                ("token", SStr("Single JWT to decode (any format that matches requestBody scan)")),
                ("tokens", SArr("Array of JWT strings to merge with page-derived tokens"))
            )),

        Tool("browser_security_jwt_forge",
            "Build a modified JWT (JWS) for security testing: merge header/payload, set nested claims via dot-path keys " +
            "(e.g. payload.data.email), optionally strip the signature (alg none flows). Does not re-sign HS256/RS256. " +
            "REST: POST /api/security/jwt-forge. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("baseToken", SStr("Existing JWT (three segments, or empty third segment)")),
                ("algorithm", SStr("Top-level alg override (e.g. none). Applied as header.alg. none also strips the signature unless stripSignature is set.")),
                ("modifications", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional: { \"header\": {…}, \"payload\": {…}, \"payload.claim.path\": value }. Shallow-merge for header/payload objects."
                }),
                ("stripSignature", SBool("Emit header.payload. with an empty signature (default false)"))
            ), ["baseToken"]),

        Tool("browser_security_jwt_acceptance_sweep",
            "Tests endpoints for missing authentication, JWT alg:none, and alg-header variants (cookie-isolated). " +
            "When endpoints[] is set, only those URLs are probed (network log skipped unless includeNetworkLog:true). " +
            "Cookie-sourced JWTs are retested via Authorization Bearer and Cookie: name=. " +
            "REST: POST /api/security/jwt-acceptance-sweep. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("host", SStr("Filter to host")),
                ("maxEndpoints", SInt("Max endpoints (default 15)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("baseToken", SStr("Optional JWT to forge alg:none variant from")),
                ("token", SStr("Alias for baseToken")),
                ("endpoints", SArr("Explicit absolute URLs to probe (strings or {url}); when set, network-log candidates are skipped by default")),
                ("includeNetworkLog", SBool("Also/only use network-log attack-surface candidates (default false when endpoints set, else true)")),
                ("cookieName", SStr("Cookie name for cookie-transport probes (e.g. _dct); auto-inferred from cookie JWT source when possible")),
                ("includeAlgVariants", SBool("Test case/whitespace/missing alg variants when canonical none rejected (default true)")),
                ("includeUnauthenticatedOnly", SBool("Skip JWT tests; only missing-auth checks")),
                ("verbose", SBool("Include jwtPayloadUsed / transport detail per row"))
            )),

        Tool("browser_security_jwt_header_abuse",
            "Tests JWT jku/x5u SSRF and kid injection/path-traversal on protected endpoints. " +
            "REST: POST /api/security/jwt-header-abuse. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("host", SStr("Filter to host")),
                ("baseToken", SStr("Optional JWT base token")),
                ("maxEndpoints", SInt("Max endpoints (default 10)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_cookie_prefix_bypass",
            "Detects __Host-/__Secure- cookie prefix parser normalization bypass via whitespace variants. " +
            "REST: POST /api/security/cookie-prefix-bypass. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("pageUrl", SStr("Page URL (default: current)")),
                ("timeoutMs", SInt("Per-request timeout (default 12000)"))
            )),

        Tool("browser_security_tls_introspection",
            "Passive TLS/certificate introspection for HTTPS origins (handshake + optional CDP). " +
            "Probes TLS 1.2+ baseline and explicit TLS 1.0/1.1 legacy support per origin. " +
            "REST: POST /api/security/tls-introspection.",
            Schema(
                ("maxOrigins", SInt("Max origins to probe (default 8)")),
                ("connectTimeoutMs", SInt("Connect timeout ms (default 8000)")),
                ("certExpiryWarningDays", SInt("Flag certs expiring within N days (default 30)")),
                ("includeNetworkOrigins", SBool("Include API origins from network log (default true)")),
                ("includeLegacyTlsProbes", SBool("Probe TLS 1.0/1.1 acceptance per origin (default true)"))
            )),

        Tool("browser_security_auth_bypass_pivot",
            "Captures a token (session, JWT analyze, or optional SQLi login bypass) and retests protected endpoints. " +
            "REST: POST /api/security/auth-bypass-pivot. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("host", SStr("Filter to host")),
                ("token", SStr("Optional bearer token")),
                ("maxEndpoints", SInt("Max endpoints to retest (default 20)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("trySqliLoginBypass", SBool("Attempt canonical SQLi login bypass if no token (default true)"))
            )),

        Tool("browser_security_rest_scaffold",
            "Probes ~20 common REST collection paths for unauthenticated JSON leaks when traffic is sparse. " +
            "REST: POST /api/security/rest-scaffold. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("baseUrl", SStr("Origin URL (default: current page)")),
                ("timeoutMs", SInt("Per-request timeout (default 12000)")),
                ("maxPaths", SInt("Max scaffold paths (default 24)"))
            )),

        Tool("browser_security_path_filter_bypass",
            "Path-filter bypass probes (NUL byte, double-encoding) on static file directory bases. " +
            "REST: POST /api/security/path-filter-bypass. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("basePath", SStr("Single directory base (e.g. /ftp/)")),
                ("pathBases", SArr("Multiple directory bases")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("maxBases", SInt("Max bases to probe (default 5)"))
            )),

        Tool("browser_security_harvest_ids",
            "Harvest object IDs from network log and DOM; suggests authz/boundary tests. " +
            "REST: POST /api/security/harvest-ids. Read-only — no safetyMode: active required.",
            Schema(
                ("host", SStr("Filter network log to host")),
                ("maxIdsPerKind", SInt("Cap per ID kind (default 12)")),
                ("includeDom", SBool("Scan DOM for data-id/href patterns (default true)"))
            )),

        Tool("browser_security_brute_force",
            "Sends N sequential failed login attempts with wrongPassword to measure lockout/rate-limit signals (status, body snippets, timing). " +
            "Cap 50 attempts. REST: POST /api/security/brute-force. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("loginUrl", SStr("Login endpoint URL")),
                ("method", SStr("HTTP method (default POST)")),
                ("headers", new Dictionary<string, object> { ["type"] = "object" }),
                ("body", SStr("Body with passwordPlaceholder replaced each attempt")),
                ("json", new Dictionary<string, object> { ["type"] = "object" }),
                ("passwordPlaceholder", SStr("Substring to replace with wrong password (default {{PASSWORD}})")),
                ("wrongPassword", SStr("Optional fixed wrong password (random if omitted)")),
                ("attempts", SInt("Number of attempts, 1-50 (default 6)")),
                ("delayMs", SInt("Delay between attempts (default 75)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_idor_scan",
            "Fetches a URL/body template with exactly one §id§ or {{id}} marker for multiple id values; compares fingerprints. " +
            "By default infers extra HTTP methods from the session network log for the same path. " +
            "DESTRUCTIVE DEFAULT IS OFF: includeMutatingProbes defaults to false — set true (or start Trowser with --dangerous-ok and omit the flag) to also try PUT/PATCH/DELETE, which can MODIFY or DELETE real resources. " +
            "Use dryRun:true to list planned HTTP requests without sending them; safeDefaults:true forces read-only IDOR and disables mutating probes. " +
            "REST: POST /api/security/idor-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL with single id marker"),
                        ["method"] = SStr("Default GET"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Optional body with marker"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("ids", SArr("String ids to try (default: 1,2,999999,0)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("methods", SArr("Optional: exact list of HTTP methods to probe (skips network inference)")),
                ("inferMethodsFromNetwork", SBool("Match session network log by path and add observed methods (default true)")),
                ("includeMutatingProbes", SBool("Also probe PUT, PATCH, DELETE (destructive; default false unless --dangerous-ok)")),
                ("readOnlyProbes", SBool("Only GET/HEAD/OPTIONS (default false; forced true with safeDefaults or --safe-probes-only)")),
                ("safeDefaults", SBool("Mutating IDOR off + read-only verbs")),
                ("dryRun", SBool("Plan probes only; no HTTP traffic"))
            )),

        Tool("browser_security_mass_assignment_scan",
            "Sends a baseline JSON or application/x-www-form-urlencoded request, then re-sends with extra privileged fields (role, UserId, balance, …). " +
            "valueReflected means that field echoed the value; valuePersisted means a follow-up fetch shows it and the baseline fetch did not. Short tokens in unrelated HTML are not a hit. " +
            "REST: POST /api/security/mass-assignment-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("Target URL"),
                        ["method"] = SStr("POST, PUT, PATCH, …"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("JSON object string or application/x-www-form-urlencoded body"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object", ["description"] = "JSON object body (alternative to body)" }
                    }
                }),
                ("privilegedFields", SArr("Optional field names to inject (e.g. role, isAdmin, UserId)")),
                ("verifyPersistence", SBool("Re-fetch resource after inject to verify field persisted (default false)")),
                ("verifyFetchUrl", SStr("URL for persistence check (default: same as request.url)")),
                ("verifyFetchMethod", SStr("Method for persistence check (default GET)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)"))
            )),

        Tool("browser_security_mass_assignment_patch",
            "PATCH/PUT self-promote mass-assignment probe (OWASP WSTG-INPV-20 / API mass-assignment): discovers profile update endpoints, " +
            "injects privileged fields (role, isAdmin, balance, …), then verifies persistence via GET /api/users/me. " +
            "REST: POST /api/security/mass-assignment-patch. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("maxFields", SInt("Max privileged fields to test (default 8)"))
            )),

        Tool("browser_security_mass_assignment_register",
            "Registration mass-assignment scaffold: probes signup/register endpoints with extra privileged fields. " +
            "Creates real user accounts — requires safetyMode: active and confirmDestructive. " +
            "REST: POST /api/security/mass-assignment-register.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("confirmDestructive", SBool("Required — creates accounts on the server")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("maxPaths", SInt("Max registration paths to probe (default 6)")),
                ("paths", SArr("Optional explicit registration URL paths"))
            ), ["confirmDestructive"]),

        Tool("browser_security_bfla_probe",
            "Broken Function Level Authorization probe: sends POST/PUT to admin paths using the current session cookies. " +
            "Discovers admin endpoints from attack surface or explicit adminPaths. " +
            "REST: POST /api/security/bfla-probe. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("baseUrl", SStr("Optional base URL override")),
                ("host", SStr("Filter attack-surface discovery to host")),
                ("timeoutMs", SInt("Per-request timeout (default 12000)")),
                ("maxEndpoints", SInt("Max admin endpoints to probe (default 12)")),
                ("adminPaths", SArr("Optional admin path prefixes")),
                ("discoverFromAttackSurface", SBool("Merge endpoints from network log (default true)"))
            )),

        Tool("browser_security_response_field_diff",
            "Excessive data exposure probe: compares JSON field paths between two captured identities on the same endpoints. " +
            "Flags fields present for low-privilege identity that should be admin-only. " +
            "Capture identities first with browser_identity_capture. REST: POST /api/security/response-field-diff.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("lowPrivilegeIdentity", SStr("Captured identity name (user role)")),
                ("highPrivilegeIdentity", SStr("Captured identity name (admin role)")),
                ("userIdentity", SStr("Alias for lowPrivilegeIdentity")),
                ("adminIdentity", SStr("Alias for highPrivilegeIdentity")),
                ("host", SStr("Filter attack-surface discovery")),
                ("endpoints", SArr("Optional explicit endpoint URLs")),
                ("maxEndpoints", SInt("Max endpoints to compare (default 10)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("discoverFromAttackSurface", SBool("Use network log endpoints (default true)"))
            )),

        Tool("browser_authz_role_matrix",
            "Authorization role matrix: fetches endpoints as each captured identity and classifies access (allowed/denied/error). " +
            "Highlights endpoints where low-privilege identity gets same response as admin. " +
            "Requires at least two captured identities. REST: POST /api/authz/role-matrix.",
            Schema(
                ("identities", SArr("Captured identity names, e.g. [\"user\", \"admin\"]")),
                ("host", SStr("Filter attack-surface discovery")),
                ("endpoints", SArr("Optional explicit endpoint URLs (method|url)")),
                ("includeAdminEndpoints", SBool("Include admin paths from attack surface (default true)")),
                ("maxEndpoints", SInt("Max endpoints in matrix (default 20)")),
                ("timeoutMs", SInt("Per-request timeout (default 15000)")),
                ("discoverFromAttackSurface", SBool("Use network log endpoints (default true)"))
            ), ["identities"]),

        Tool("browser_sse_connections",
            "List captured Server-Sent Events (EventSource) streams on the active tab. REST: GET /api/sse/connections.",
            Schema(
                ("url", SStr("Filter by URL substring")),
                ("state", SStr("Filter by state: open, closed, or all (default all)")),
                ("tabIndex", SInt("Tab index (default active)"))
            )),

        Tool("browser_sse_messages",
            "List SSE event messages captured via CDP. REST: GET /api/sse/messages.",
            Schema(
                ("connectionId", SInt("Stream connection id from browser_sse_connections")),
                ("event", SStr("Filter by event name")),
                ("limit", SInt("Max messages (default 100)")),
                ("tabIndex", SInt("Tab index (default active)"))
            )),

        Tool("browser_security_sse_audit",
            "Audit Server-Sent Events: CORS/credentials screening, sensitive data in events, dangerous EventSource handlers, " +
            "and optional active checks (unauthenticated subscribe, cross-origin proof, Last-Event-ID replay, peer). " +
            "Browse EventSource flows first. REST: POST /api/security/sse-audit. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("safe (passive + GET active caps) | active (POST streams)")),
                ("connectionId", SInt("Audit one stream connection")),
                ("checks", SArr("Check names or all (default all)")),
                ("maxEvents", SInt("Active read event cap (default 50)")),
                ("maxMs", SInt("Active read time cap ms (default 5000)")),
                ("useCapturedShapeHeaders", SBool("Copy non-auth owner headers on active probes (default true)"))
            )),

        Tool("browser_websocket_send",
            "Send a message on an active WebSocket connection via injected page hook. " +
            "REST: POST /api/websocket/send. Blocked in safe mode.",
            Schema(
                ("connectionId", SInt("WebSocket connection ID from GET /api/websocket/connections")),
                ("message", SStr("Message payload to send"))
            )),

        Tool("browser_websocket_close",
            "Close an active WebSocket connection via injected page hook. " +
            "REST: POST /api/websocket/close. Blocked in safe mode.",
            Schema(
                ("connectionId", SInt("WebSocket connection ID")),
                ("code", SInt("Optional close code (default 1000)")),
                ("reason", SStr("Optional close reason"))
            )),

        Tool("browser_security_websocket_fuzz",
            "Active WebSocket message fuzzing. Sends XSS/SQLi/JSON-breaking payload catalogs via websocket/send, " +
            "audits received frames for reflection/HTML/SQLi indicators, and replays privileged message types. " +
            "Requires active WebSocket connections from browsing the app. Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("connectionId", SInt("Fuzz a specific connection (default: all open)")),
                ("payloadSets", SArr("Fuzzer payload set names (default: xss-basic, sqli-basic, json-breaking)")),
                ("maxPayloadsPerSet", SInt("Max payloads per set (default: 8)")),
                ("payloadProfile", SStr("Payload corpus breadth for built-in sets: small (default) | big")),
                ("includeMessageTypeMatrix", SBool("Replay privileged JSON message types (default: true)")),
                ("responseWaitMs", SInt("Wait after send before checking frames ms (default: 500)"))
            )),

        Tool("browser_security_websocket_authz",
            "Cross-identity WebSocket check. Sends one captured sent frame on a peer's already-open socket and classifies the next frames " +
            "(ConfirmedLeak, BolaSuspected, SameShapeDifferentData, ProperlyDenied, Inconclusive). " +
            "Not HTTP BOLA: the peer must be browsing with that socket open. Read-like frames (subscribe, query, ping) need safetyMode safe; " +
            "other frames need active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: safe for subscribe/query/ping frames; active for other frames")),
                ("connectionId", SInt("Owner WebSocket connection ID from GET /api/websocket/connections")),
                ("frameId", SInt("Optional sent frame id. Default: latest sent text frame")),
                ("message", SStr("Optional frame text. Default: the captured sent frame")),
                ("peer", SStr("Peer name. Omit to test every registered peer")),
                ("responseWaitMs", SInt("Wait after send before reading peer frames (default 800)"))
            )),

        Tool("browser_security_auto_scan",
            "Attack-surface-to-scan pipeline: discover endpoints from traffic (+ optional OpenAPI enrichment), then run targeted scanners " +
            "(SQLi, SSTI, IDOR, CSRF, path-traversal, SSRF, open-redirect, mass-assignment, …). Browse first. REST: POST /api/security/auto-scan. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("host", SStr("Filter endpoints to a specific host (default: all captured hosts)")),
                ("maxEndpointsPerScanner", SInt("Max endpoints each scanner tests (default 5)")),
                ("timeoutMs", SInt("Per-request timeout in ms (default 15000)")),
                ("includeSqli", SBool("Run SQL injection scanner (default true)")),
                ("includeIdor", SBool("Run IDOR scanner (default true)")),
                ("includeCsrf", SBool("Run CSRF scanner (default true)")),
                ("includePathTraversal", SBool("Run path traversal scanner (default true)")),
                ("includeSsrf", SBool("Run SSRF scanner on URL-like parameters (default true)")),
                ("includeOpenRedirect", SBool("Run open redirect scanner on redirect/url/next parameters (default true)")),
                ("includeCacheDeception", SBool("Run cache deception scan when session cookies present (default true)")),
                ("includeCacheMap", SBool("Run cache-map indication (identify + busted key mapping; default true)")),
                ("includeSsti", SBool("Run SSTI micro-scanner ({{7*7}} / ${7*7} reflection) (default true)")),
                ("includeSstiPolyglot", SBool("Run fast SSTI polyglot GET probe (default true)")),
                ("includeSstiStored", SBool("Run stored SSTI profile POST+GET probe (default true)")),
                ("includePrototypePollution", SBool("Run server-side prototype pollution scan (default true)")),
                ("scanDepth", SStr("Scan breadth: quick | standard (default) | thorough — polyglot caps and per-scanner limits")),
                ("payloadProfile", SStr("Payload corpus breadth: small (default, built-in) | big (extended corpora subsets)")),
                ("includeCsti", SBool("Run CSTI DOM scan (default: auto when AngularJS/Vue/Handlebars detected; set false to skip, true to force)")),
                ("includeXss", SBool("Run reflected XSS scan on injectable parameters (default true)")),
                ("includeXssDom", SBool("Run DOM XSS probes via browser navigation (default true)")),
                ("includeXssStored", SBool("Run stored XSS POST+readback probes (default true)")),
                ("includeParserProbe", SBool("Run parser-probe on JSON endpoints (default false)")),
                ("includeCmdCanary", SBool("Run cmd-canary on injectable params (default true)")),
                ("includeNosql", SBool("Run NoSQL injection scan (default true)")),
                ("includeLdap", SBool("Run LDAP injection scan on login endpoints (default true)")),
                ("includeSqliLoginSweep", SBool("Run SQLi login bypass sweep (default true)")),
                ("sparseInjectionThreshold", SInt("When attack-surface endpoints below this, also run ALWAYS_PROBED SQLi templates (default 3)")),
                ("includeApiEnrichment", SBool("Merge OpenAPI/JS bundle hints before scanning (default true)")),
                ("includeMassAssignment", SBool("Run mass assignment scanner (default true)")),
                ("includeMassAssignmentPatch", SBool("Run PATCH/PUT self-promote probe (destructive; default false)")),
                ("includeMassAssignmentRegister", SBool("Run registration mass-assignment scaffold (destructive; default false)")),
                ("includeBflaAdminProbe", SBool("Run BFLA admin POST/PUT probe (default true)")),
                ("includeIdorMutatingProbes", SBool("IDOR: also PUT/PATCH/DELETE (destructive; default false unless --dangerous-ok)")),
                ("idorReadOnlyProbes", SBool("IDOR: only GET/HEAD/OPTIONS")),
                ("safeDefaults", SBool("Read-only IDOR + skip mass-assignment")),
                ("minPriority", SStr("Minimum endpoint priority to scan: low, medium, high, critical (default: low)")),
                ("includeChainAnalysis", SBool("Run chain-analyze after scanners and include chains/partial chains in response (default false)")),
                ("minChainedSeverity", SStr("Minimum chained severity when includeChainAnalysis is true")),
                ("includePartial", SBool("Include partial chains with suggested next tests (default true)")),
                ("customProbes", SObjArr("Array of custom probe objects for domain-specific checks. Each probe: { name, url, method?, headers?, body?, severity?, expectStatus?, failIfBodyContains?, failIfBodyMissing?, failIfStatusRange? (e.g. '200-299') }. Use for CAPTCHA bypass, JWT algorithm confusion, null byte traversal, etc."))
            )),

        Tool("browser_security_secrets_harvest",
            "Unified secret/credential harvesting across all browser sources: " +
            "JS bundles (hardcoded creds, API keys), cookies & storage (JWTs, tokens, PII), " +
            "network responses (leaked credentials, bearer tokens), visible page text (debug output), " +
            "and source maps (exposed source code). Returns deduplicated, severity-prioritized findings. " +
            "safetyMode 'safe' runs passive sources (cookies/storage, network log, page text); 'active' also " +
            "fetches JS bundles and source maps. REST: POST /api/security/secrets-harvest.",
            Schema(
                ("safetyMode", SStr("Safety mode: safe (passive sources) | active (also fetch JS/source maps) | aggressive. Default: safe")),
                ("includeJsBundles", SBool("Scan JS script[src] assets for hardcoded secrets (active only; default true)")),
                ("includeCookiesAndStorage", SBool("Analyze cookies, localStorage, sessionStorage for tokens/PII (default true)")),
                ("includeNetworkResponses", SBool("Scan captured network response bodies for credential exposure (default true)")),
                ("includePageText", SBool("Scan visible page text for secrets/debug output (default true)")),
                ("includeSourceMaps", SBool("Check for exposed source maps and debug mode (active only; default true)")),
                ("maxJsScripts", SInt("Max JS scripts to fetch and scan (default 20)")),
                ("maxNetworkResponses", SInt("Max network response bodies to scan (default 100)")),
                ("maxBytesPerFile", SInt("Max bytes read per JS bundle (default 1048576)")),
                ("includeHtmlComments", SBool("Scan HTML comments in page source (default true)")),
                ("timeoutMs", SInt("Timeout for JS bundle fetches in ms (default 30000)"))
            )),

        Tool("browser_security_oidc_analyze",
            "OIDC session dossier, optional provider metadata, and relying-party JWT checks. Tries openid-configuration and oauth-authorization-server; many IdPs omit discovery — other checks still run. " +
            "BFF/proxy login: pass issuer; login UI host is not the issuer. testDynamicRegistration requires safetyMode: active. REST: POST /api/security/oidc-analyze.",
            Schema(
                ("issuer", SStr("OIDC issuer URL (e.g. https://login.example.com/realms/myrealm). Omit for auto-detection. Required for a BFF/proxy login, where the browser does not see the issuer.")),
                ("autoDetect", SBool("Auto-detect issuer from network traffic: JWTs, authorize URLs, .well-known fetches (default: true)")),
                ("probeEndpoints", SBool("Probe all discovered endpoints for reachability when discovery exists (default: true)")),
                ("testDynamicRegistration", SBool("POST open registration probe (default: false; requires safetyMode: active)")),
                ("testGrantTypes", SBool("Actively probe token endpoint with detected client IDs to verify if dangerous grant types (password, client_credentials) are usable (default: false)")),
                ("validateRpTokens", SBool("Validate JWTs visible in browser against JWKS when available (default: true)")),
                ("clientId", SStr("Explicit client_id to test. If omitted, auto-detected from network log (authorize URLs, token requests, JWT aud/azp claims)")),
                ("timeoutMs", SInt("HTTP request timeout in ms (default: 20000)"))
            )),

        Tool("browser_security_oauth_flow_test",
            "OAuth2/OIDC authorization-flow checks from captured /authorize+callback traffic (state/PKCE/implicit/mix-up) " +
            "plus optional active probes when safetyMode: active. Returns dossier. passiveOnly: true works under CLI --safe. Active code replay uses captured codes from the log (not forged by default). BFF: no authorize URL. REST: POST /api/security/oauth-flow-test.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required for active probes) | aggressive. Default: safe. Omit when passiveOnly: true")),
                ("passiveOnly", SBool("Only analyze network log and browser leaks; no authorize/token HTTP probes (default: false; use true first)")),
                ("authorizationUrl", SStr("Baseline authorize URL. Omit to auto-detect from network log")),
                ("tokenEndpoint", SStr("Token endpoint URL (auto-detected from network log when omitted)")),
                ("clientId", SStr("OAuth client_id (auto-detected when omitted)")),
                ("redirectUri", SStr("Registered redirect_uri (auto-detected when omitted)")),
                ("issuer", SStr("OIDC issuer — used to build authorize URL from discovery when no traffic captured")),
                ("autoDetect", SBool("Auto-detect flow parameters from network log (default: true)")),
                ("checkBrowserLeaks", SBool("Check window.opener, document.referrer, hash tokens on current page (default: true)")),
                ("skipRedirectUriTests", SBool("Skip redirect_uri manipulation probes")),
                ("skipStateTests", SBool("Skip state parameter probes")),
                ("skipPkceTests", SBool("Skip PKCE probes")),
                ("skipScopeTests", SBool("Skip scope escalation probe")),
                ("skipResponseTypeTests", SBool("Skip implicit flow downgrade probe")),
                ("skipTokenExchange", SBool("Skip authorization-code replay at token endpoint")),
                ("useCanaryTokenExchange", SBool("Use forged code when no captured code exists (legacy canary; default: false)")),
                ("holdCallback", SBool("Reserved: future callback-intercept binding probes")),
                ("flowBreaker", SBool("After HTTP probes, confirm flagged mutations in browser (active; may consume auth codes)")),
                ("maxBrowserSteps", SInt("Max live authorize navigations for flowBreaker (default: 2, max: 5)")),
                ("mutations", SArr("Explicit authorize URLs for flowBreaker browser steps")),
                ("timeoutMs", SInt("HTTP timeout per probe in ms (default: 15000)"))
            )),

        Tool("browser_security_graphql_analyze",
            "GraphQL security analysis (introspection, mutations, batching, aliases, depth/limit, draft access, field suggestions, rate limits). " +
            "Auto-detects endpoint from network log. REST: POST /api/security/graphql-analyze. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("GraphQL endpoint URL. Omit for auto-detection from network log")),
                ("headers", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "HTTP headers to include (e.g. Authorization). Keys are header names, values are header values."
                }),
                ("autoDetect", SBool("Auto-detect GraphQL URL from network traffic (default: true)")),
                ("timeoutMs", SInt("Overall timeout in ms (default: 30000)")),
                ("skipIntrospection", SBool("Skip introspection test")),
                ("skipBatching", SBool("Skip query batching test")),
                ("skipAmplification", SBool("Skip alias amplification test")),
                ("skipDepthProbe", SBool("Skip depth limit probe")),
                ("skipLimitProbe", SBool("Skip max limit test")),
                ("skipFieldSuggestion", SBool("Skip field suggestion exploitation test")),
                ("skipDraftAccess", SBool("Skip draft/preview access test"))
            )),

        Tool("browser_security_verify",
            "Exploit verifier: injects payload via browser fetch (optional), navigates to renderUrl with structured " +
            "query/hash/path injection (renderInjection), evaluates effectCheck, returns evidence + screenshot. " +
            "Use renderInjection for DOM XSS (fragmentEncode: none). skipInjection or omit injection when payload " +
            "is delivered only via navigation. Fragment-aware §MARKER§ substitution via fragmentEncode/queryEncode. " +
            "Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("injection", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional when renderInjection + skipInjection. { url, method?, headers?, body?|json? }",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("Target URL for fetch()"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Raw body string"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object", ["description"] = "JSON body alternative to body" }
                    }
                }),
                ("skipInjection", SBool("Skip injection fetch — payload delivered via renderUrl/renderInjection only (DOM XSS)")),
                ("payload", SStr("Substitutes §PAYLOAD§ / {{PAYLOAD}} and renderInjection value")),
                ("substitutions", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Optional map of marker name to string" }),
                ("renderUrl", SStr("Base URL to navigate after injection (where effect should appear)")),
                ("renderInjection", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Structured payload placement: { part: query|hash|path, param?, encode?, append? }",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["part"] = SStr("query, hash, or path"),
                        ["param"] = SStr("Parameter name — omit for entire hash fragment"),
                        ["encode"] = SStr("none | component | form"),
                        ["append"] = SBool("Append to existing hash fragment")
                    }
                }),
                ("queryEncode", SStr("Encoding for query markers (default: component)")),
                ("fragmentEncode", SStr("Encoding for hash/fragment markers (default: none)")),
                ("effectCheck", SStr("JavaScript expression evaluated on the render page, e.g. window.__xss_proof === 1")),
                ("cleanup", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional { url, method?, headers?, body?|json? }"
                }),
                ("encodePayloadInUrl", SBool("URI-encode query markers in template URLs (default true)")),
                ("waitAfterRenderMs", SInt("Delay ms after navigation before effect check")),
                ("waitForIdleAfterRender", SBool("Wait for network idle after render")),
                ("includeScreenshot", SBool("Include base64 screenshot in evidence (default true)")),
                ("screenshotFormat", SStr("jpeg or png")),
                ("fetchTimeoutMs", SInt("Per-fetch timeout ms"))
            )),

        Tool("browser_security_verify_workflow",
            "Primary proof API: setup → trigger → oracle → cleanup workflow with deterministic oracle verdict. " +
            "Step types: identity, navigate, fetch, wait, inject, screenshot, capture. Oracle types: fetch, effectCheck, " +
            "expression, domDiff, networkMatch, peerFetch, and/or. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("name", SStr("Workflow name")),
                ("setup", SArr("Setup phase steps")),
                ("trigger", SArr("Trigger phase steps")),
                ("oracle", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Oracle spec { type, checks?, ... }" }),
                ("cleanup", SArr("Cleanup phase steps")),
                ("exportEvidence", SBool("Write evidence bundle to %LocalAppData%\\Trowser\\Evidence\\"))
            ), ["oracle"]),

        Tool("browser_security_chain_prove",
            "Execute a built-in proof template for a chain patternId. Auto-substitutes {{endpoint}} from findings; pass vars for template-specific placeholders (e.g. transaction-rollback-proof). Requires safetyMode: active. " +
            "On failure read failureSummary (short), failureReason/stepErrors (detail), templateExpanded, and attemptedSubstitutions — do not treat a thin summary as missing diagnostics.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("patternId", SStr("Chain pattern ID e.g. idor-weak-auth-unauth-access")),
                ("endpoint", SStr("Override sensitive endpoint URL for template substitution")),
                ("sensitiveEndpoint", SStr("Alias for endpoint / endpoint0")),
                ("corsEndpoint", SStr("Override CORS endpoint URL (endpoint1 in templates)")),
                ("vars", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Template variable overrides (merged after finding-based substitution). Aliases: substitutions, templateVars. Example: balanceUrl, step1Url, step1Body for fail-open-transaction."
                }),
                ("exportEvidence", SBool("Export evidence bundle after proof"))
            ), ["patternId"]),

        Tool("browser_repro_capture",
            "Capture a .trw repro from journal actions since a checkpoint. " +
            "Pass checkpointId to bound the slice (defaults to the latest checkpoint, or all actions if none). " +
            "Optionally write the file with path and attach an oracle. REST: POST /api/repro/capture.",
            Schema(
                ("checkpointId", SStr("Checkpoint id to slice from (default: latest)")),
                ("name", SStr("Name stored on the .trw")),
                ("path", SStr("Optional file path to write the .trw")),
                ("outputPath", SStr("Alias for path")),
                ("oracle", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Optional workflow oracle attached to the captured .trw" })
            )),

        Tool("browser_repro_verify",
            "Replay a captured .trw, evidence bundle, or workflow k times. Clears the session and optionally applies an identity between runs. " +
            "Returns reproducible | flaky | not-reproducible with a pass rate. Requires safetyMode: active. REST: POST /api/repro/verify.",
            Schema(
                ("safetyMode", SStr("Must be 'active' to run the workflow")),
                ("trwPath", SStr("Path to a .trw / .json scenario")),
                ("file", SStr("Alias for trwPath")),
                ("bundlePath", SStr("Evidence bundle directory containing workflow.json")),
                ("workflow", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Inline workflow (setup/trigger/oracle) or flat steps" }),
                ("runs", SInt("How many times to replay (default 1, max 20)")),
                ("clearSession", SBool("Clear test artifacts between runs (default true)")),
                ("identity", SStr("Identity name to apply before each run")),
                ("expect", SStr("Optional expected verdict: reproducible | flaky | not-reproducible (also accepts VERIFIED / NOT_VERIFIED)"))
            )),

        Tool("browser_vpx_export",
            "Export session security findings as a VPX 1.1 document (Vulnerability Proof eXchange). " +
            "Includes runs, surfaces, findings, assessments, proofs, artifacts, and verdicts. " +
            "Read-only — allowed in safe mode. REST: GET /api/vpx/export. Spec: VPX/spec/VPX-1.1.md.",
            Schema(
                ("profile", SStr("compact (default) or full"))
            )),

        Tool("browser_vpx_import",
            "Import a VPX 1.1 document (VPX 1.0 also accepted) — registers findings for proof queue, surfaces, runs, assessments, proofs, artifacts, and verdicts. " +
            "mode: merge (default) or replace. action: clear removes imported VPX state and resets cross-playbook dedup. " +
            "Read-only ingestion — allowed in safe mode. REST: POST /api/vpx/import. " +
            "Guides: VPX/guides/LLM-AUTHOR-GUIDE.md, VPX/guides/RUNTIME-AUTHOR-GUIDE.md.",
            Schema(
                ("document", new Dictionary<string, object> { ["type"] = "object", ["description"] = "VPX 1.1 document (VPX 1.0 also accepted; or pass fields inline)" }),
                ("mode", SStr("merge (default) or replace")),
                ("action", SStr("clear — remove VPX import state and reset cross-playbook dedup"))
            )),

        Tool("browser_vpx_clear",
            "Clear VPX import state and cross-playbook finding dedup (manual chain findings + auto-scan feed). " +
            "Use between iterative playbook runs. Read-only — allowed in safe mode. REST: POST /api/vpx/clear.",
            Schema()),

        Tool("browser_security_chain_analyze",
            "Attack chain discovery: analyzes shadow, auto-scan, and manual findings against built-in chain patterns " +
            "(CSRF→XSS worm, open redirect→OAuth hijack, IDOR+weak auth, etc.). Returns full chains and partial chains " +
            "with suggestedAction hints for missing links. Read-only — allowed in safe mode. " +
            "REST: POST /api/security/chain-analyze.",
            Schema(
                ("minChainedSeverity", SStr("Minimum chained severity to include: critical, high, medium, low")),
                ("includePartial", SBool("Include partial chains with one missing link (default true)"))
            )),

        Tool("browser_security_chain_patterns",
            "List or manage attack chain patterns. action=list (default) returns built-in + custom patterns with links and proofTemplateId. " +
            "action=add accepts full links[] (requiredCategory, role, optional, constraint), proofTemplateId, description narrative, severity, impact — or legacy categories[] (min 2). " +
            "action=remove deletes custom patterns (blocked in safe mode). Read-only list allowed in safe mode. " +
            "REST: GET/POST /api/security/chain-patterns.",
            Schema(
                ("action", SStr("list (default), add, or remove")),
                ("id", SStr("Pattern ID (required for add/remove)")),
                ("name", SStr("Pattern name (required for add)")),
                ("description", SStr("Narrative template with {0}, {1} placeholders")),
                ("severity", SStr("Chained severity: critical, high, medium (default high)")),
                ("impact", SStr("Impact category e.g. account-takeover, data-breach, rce")),
                ("proofTemplateId", SStr("Proof template key from ProofTemplateCatalog (enables chain-prove)")),
                ("links", SObjArr("Full chain links: [{ requiredCategory, role?, optional?, constraint?, endpointPattern? }] — min 2")),
                ("categories", SArr("Legacy shorthand: category names only (min 2, required if links omitted)"))
            )),

        Tool("browser_security_callbacks",
            "Out-of-band (OOB) interaction detection for blind vulnerability testing. " +
            "Monitors the browser's network log for requests to a callback domain (default: callback.trowser.test). " +
            "When injected payloads cause unexpected outbound requests (blind XSS, DOM SSRF, CSS exfiltration), " +
            "they appear here. Use action='start' to begin monitoring, 'status' to check for interactions, " +
            "'stop' to disable, 'clear' to reset. Use {{CALLBACK}} marker in fuzz payloads (ASCII-safe; auto-substituted " +
            "with the callback URL). Legacy section-sign CALLBACK marker is still accepted. Unlike proxy tools, this catches client-side OOB " +
            "that never leaves the browser.",
            Schema(
                ("action", SStr("Action: 'start' (begin monitoring), 'stop', 'status' (get interactions, default), 'clear'")),
                ("domain", SStr("Custom callback domain (default: callback.trowser.test)"))
            )),

        Tool("browser_security_csrf",
            "CSRF assessment from live page + network log (forms, missing tokens, custom-header replay, optional Referer/JSON probes). " +
            "Default: current origin only (host/allHosts to widen). Requires safetyMode: active for probes.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("host", SStr("Filter to a specific host (default: current page host; localhost/127.0.0.1 match). Use allHosts for full session + third-party.")),
                ("allHosts", SBool("Use full session network log and all hosts (default: false — page-scoped same-origin only)")),
                ("maxEndpoints", SInt("Maximum number of token-bearing endpoints to probe (default: 5)")),
                ("maxUnprotected", SInt("Maximum endpoints to report with no CSRF token observed (default: 10)")),
                ("includeGet", SBool("Probe GET endpoints that already include CSRF tokens with missing/invalid token tests (default: false). GET form DOM analysis always runs.")),
                ("includeRefererBypass", SBool("Probe Referer validation and bypass variants on state-changing endpoints via backend HttpClient (default: true)")),
                ("maxRefererEndpoints", SInt("Maximum state-changing endpoints for Referer bypass analysis (default: 5)")),
                ("includeJsonApiProbing", SBool("Probe JSON API Content-Type / method override CSRF vectors (default: true)")),
                ("maxJsonApiProbes", SInt("Max JSON API CSRF probes (default: 10)")),
                ("includeCustomHeaderProbes", SBool("Test simple-request CSRF bypass (omit X-Requested-With, text/plain) (default: true)")),
                ("maxCustomHeaderProbes", SInt("Max custom-header CSRF probes (default: 5)")),
                ("includeSameSiteAnalysis", SBool("Analyze session cookie SameSite and adjust severity (default: true)")),
                ("includeCrossSiteProof", SBool("Browser-faithful CSRF from mocked evil.trowser.test (iframe POST, fetch credentials, top-level POST). Default false.")),
                ("maxCrossSiteProbes", SInt("Max cross-site browser probes when includeCrossSiteProof is true (default: 3)")),
                ("attackerSite", SStr("cross-site (evil.trowser.test) or same-site (evil-samesite.{victimHost}) for SameSite experiments"))
            )),

        Tool("browser_security_path_traversal",
            "Path traversal probe. Default mode (query): fuzz path-like query parameters on GET URLs from the log or explicit urls. " +
            "mode path / path-append: append traversal payloads to the URL path after basePath or pathBases (for vulns in the path, not query). " +
            "Flags responses that look like /etc/passwd, win.ini, or hosts file content. " +
            "Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("mode", SStr("query (default) or path / path-append — append payloads to URL path")),
                ("basePath", SStr("Path prefix for path mode (e.g. Gruyere user root /id/...)")),
                ("pathBases", SArr("Multiple path prefixes for path mode (optional)")),
                ("urls", SArr("Optional explicit URLs to fuzz (must include a fuzzable query param in query mode)")),
                ("paramNames", SArr("Query parameter names to fuzz (defaults to file, path, page, doc, content, url, ...)")),
                ("payloads", SArr("Custom traversal payloads (optional)")),
                ("maxCandidates", SInt("Max distinct URLs (query mode) or base paths (path mode) to probe (default: 12)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_ssrf_scan",
            "SSRF scanner with unified findings (severity/confidence/tier/endpoint/param/nextActions). " +
            "Discovers URL-like parameters from network log, DOM forms/links, or explicit urls / endpointHints / scope; " +
            "injects internal IPs, cloud metadata, protocol handlers, and callback probes; optional XXE. " +
            "Default minConfidence=likely; includeHygiene=false. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional explicit request template with §ssrf§ marker",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("URL template with §ssrf§ or {{ssrf}}"),
                        ["method"] = SStr("HTTP method (default GET)"),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object" },
                        ["body"] = SStr("Body template with markers"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object" }
                    }
                }),
                ("marker", SStr("Marker name in request template (default: first marker found, usually ssrf)")),
                ("baselineValue", SStr("Baseline value for template marker substitution (default: https://example.com)")),
                ("urls", SArr("Optional explicit URLs to probe (discovery mode)")),
                ("endpointHints", SObjArr("SSRF candidate endpoints: [{ url, paramNames[], method?, requestBodySample?, headers? }]")),
                ("scope", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional scope: { host, urls[] } for allowed hosts and known SSRF endpoints",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["host"] = SStr("Target host/origin (e.g. ginandjuice.shop)"),
                        ["urls"] = SArr("Known SSRF-candidate endpoint URLs")
                    }
                }),
                ("allowedHosts", SArr("Restrict discovery to these hosts/origins (defaults to current page)")),
                ("paramNames", SArr("Parameter names to treat as URL-like (defaults to url, redirect, callback, webhook, ...)")),
                ("payloads", SArr("Custom SSRF payloads (optional; default uses built-in ssrf set)")),
                ("maxCandidates", SInt("Max distinct parameter injection points to probe (default: 10)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)")),
                ("callbackWaitMs", SInt("Ms to wait before polling Tier 1 callbacks (default: 2000)")),
                ("includeInternalIps", SBool("Inject internal/metadata IP payloads (default: true)")),
                ("includeProtocolHandlers", SBool("Inject file/gopher/dict payloads (default: true)")),
                ("includeCallbackProbes", SBool("Inject callback.trowser.test probe URLs and correlate OOB hits (default: true)")),
                ("includeDomDiscovery", SBool("Scan page hrefs for URL-like params when network log is sparse (default: true)")),
                ("includeXxe", SBool("Probe XML endpoints from network log for XXE-based SSRF (default: true)")),
                ("includeUploadXxe", SBool("Also run upload-path XXE on /file-upload, /api/import, etc. (default: false)")),
                ("includeScaffoldPaths", SBool("When no candidates found, probe built-in /api/fetch, /api/proxy, … paths (default: true)")),
                ("includeImdsV2Pivot", SBool("Attempt AWS IMDSv2 token then creds pivot (default: true)")),
                ("includeCloudMetadataHeaders", SBool("Send Metadata-Flavor / Metadata headers on GCP/Azure probes (default: true)")),
                ("useBackendFetch", SBool("Use server-side HttpClient instead of in-page fetch (default: false)")),
                ("includeBrowserCookies", SBool("When useBackendFetch, attach session cookies (default: false)")),
                ("xxePayloads", SArr("Custom XXE payloads (optional; default uses built-in xxe set)")),
                ("minConfidence", SStr("Minimum confidence to report: tentative, likely (default), or confirmed")),
                ("callbackDomain", SStr("Custom callback domain for Tier 1 OOB (optional)"))
            )),

        Tool("browser_security_ssrf_orchestrator",
            "SSRF orchestrator — one call runs scaffold paths + ssrf-scan (IMDSv2, cloud metadata headers) + " +
            "open-redirect SSRF escalation + jwt-header-abuse (jku/x5u) + callback poll + chain-analyze for ssrf-cloud-metadata. " +
            "Registers findings for chain-prove ssrf-cloud-metadata-proof. Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("urls", SArr("Optional explicit URLs to probe")),
                ("maxCandidates", SInt("Max injection points (default: 10)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)")),
                ("callbackWaitMs", SInt("Ms to wait before polling callbacks (default: 2000)")),
                ("includeScaffoldPaths", SBool("Probe built-in fetch/proxy/webhook paths when log is empty (default: true)")),
                ("includeImdsV2Pivot", SBool("AWS IMDSv2 token→creds pivot (default: true)")),
                ("includeCloudMetadataHeaders", SBool("GCP/Azure metadata headers on app-facing requests (default: true)")),
                ("includeXxe", SBool("Include XXE-based SSRF probes (default: true)")),
                ("includeUploadXxe", SBool("Include upload-path XXE (default: false)")),
                ("includeOpenRedirect", SBool("Run open-redirect scan with SSRF escalation (default: true)")),
                ("includeJwtHeaderAbuse", SBool("Run JWT jku/x5u SSRF probe (default: true)")),
                ("includeCallbackProbes", SBool("Inject callback probe URLs (default: true)")),
                ("includeChainAnalysis", SBool("Run chain-analyze after scans (default: true)")),
                ("registerChainFindings", SBool("Register findings for chain-prove (default: true)")),
                ("callbackDomain", SStr("Custom callback domain (optional)")),
                ("minConfidence", SStr("Minimum SSRF confidence: likely (default), confirmed, or tentative"))
            )),

        Tool("browser_security_open_redirect_scan",
            "Open redirect scanner (CWE-601). Discovers redirect/url/next/return_to parameters from network log " +
            "(or explicit urls / endpointHints), probes with external URLs using redirect:manual, and checks whether " +
            "the Location header points off-site. Includes bypass payloads (protocol-relative, backslash, @-trick). " +
            "Use endpointHints when attack surface found redirect params but captured URLs lack query strings. " +
            "Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("urls", SArr("Optional explicit URLs to probe (discovery mode)")),
                ("endpointHints", SObjArr("Endpoints with redirect params but no query in URL: [{ url, paramNames[], method? }]")),
                ("paramNames", SArr("Parameter names to treat as redirect targets (defaults to redirect, url, next, return_to, ...)")),
                ("payloads", SArr("Custom open-redirect payloads (optional; default uses built-in bypass set)")),
                ("probeHost", SStr("Host to probe for in Location header (default: open-redirect-probe.trowser.test)")),
                ("includeDomDiscovery", SBool("Scan page hrefs for redirect params when network log is empty (default: true)")),
                ("includeAdaptiveBypasses", SBool("Include javascript:/data: payloads and log filter insights (default: true)")),
                ("includeSsrfEscalationProbes", SBool("After open redirect, probe file:// and internal IPs (default: true)")),
                ("maxCandidates", SInt("Max distinct parameter injection points to probe (default: 12)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_cache_deception_scan",
            "Web Cache Deception (WCD) scanner. Probes delimiter path variants (/api/me/.css, ;.css, etc.) " +
            "with authenticated then anonymous requests; flags byte-equal responses (cached authed body served to anon). " +
            "Always includes the current page path. Requires logged-in session. Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("paths", SArr("Base paths to test (default: current page + /api/me, /account, /dashboard, ...)")),
                ("maxCandidates", SInt("Max variant URLs (default: 12)")),
                ("minBodySize", SInt("Minimum body length for match (default: 64)")),
                ("requireSession", SBool("Skip when no session cookies (default: true)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_cache_map",
            "Cache identification + key-mapping indication. Unique ?trowser_cb= busters only — does not poison the live URL. " +
            "safetyMode safe: identify + query/path mapping. active: also probes a small header set and fat GET (still busted). " +
            "Logged-in cookies by default. If a cache is identified, nextActions point at cache-pollution-scan.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe (default) | active | aggressive")),
                ("urls", SArr("Target URLs (default: current page + up to 1 cacheable same-origin asset)")),
                ("maxTargets", SInt("Max URLs (default: 2)")),
                ("includeBrowserCookies", SBool("Include session cookies (default: true)")),
                ("headers", SArr("Restrict active header probes to these names")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_cache_pollution_scan",
            "Live-key error pollution: miss-forcing header on the clean URL, then error-inducing headers, then a fully clean GET. " +
            "No query buster. A confirmed hit stores an error on the shared URL. Requires safetyMode: active. Blocked in --safe.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("urls", SArr("Target URL (default: current page; no query buster is added)")),
                ("includeBrowserCookies", SBool("Include session cookies (default: false; public-cache attack)")),
                ("cacheReplayDelayMs", SInt("Delay before clean confirm ms (default: 300)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_cache_poison_scan",
            "Classic web cache poisoning scanner. Injects canary values via unkeyed headers " +
            "(X-Forwarded-Host, X-Original-URL, ...) then replays a clean GET to detect cache persistence. " +
            "Prefer bypassHeader from cache-pollution-scan for the live key. Query buster is opt-in (weaker). " +
            "Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("urls", SArr("Target URLs (default: current page)")),
                ("headers", SArr("Unkeyed headers to probe (default: built-in set)")),
                ("canaryHost", SStr("Canary host (default: cache-poison-probe.trowser.test)")),
                ("bypassHeader", SStr("Miss-forcing header from cache-pollution identify step (live-key)")),
                ("bypassHeaderValue", SStr("Value for bypassHeader (default: no-cache / 1)")),
                ("useQueryBuster", SBool("Opt-in private-slot ?trowser_cb= (default false; weaker proof)")),
                ("includeBrowserCookies", SBool("Include session cookies (default: false)")),
                ("includeHeaderInjectionFuzz", SBool("Also fuzz X-Forwarded-Host with header-injection payloads (default: false)")),
                ("maxTargets", SInt("Max URLs to test (default: 3)")),
                ("cacheReplayDelayMs", SInt("Delay before cache-oracle replay ms (default: 300)")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)"))
            )),

        Tool("browser_security_methods",
            "Test which HTTP methods are allowed on a URL. Sends GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, and TRACE " +
            "requests and reports which are accepted. Flags security issues like enabled TRACE (XST risk) and " +
            "unrestricted PUT/DELETE. Uses server-side HttpClient to test methods blocked by browsers.",
            Schema(
                ("url", SStr("URL to test (default: current page URL)"))
            )),

        Tool("browser_security_smuggling",
            "HTTP Request Smuggling scan via raw TCP. Confirmed = repeated differential 404 (CL.TE/TE.CL canary prefix). " +
            "Timing, TE obfuscation, duplicate Content-Length, and HEADER hygiene are informational notes, not bugs. " +
            "Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("URL to test (default: current page URL)")),
                ("techniques", SArr("Techniques to test: all (default), CL-TE, TE-CL, TE-TE, CL-CL, HEADER")),
                ("timeoutMs", SInt("Per-probe timeout in ms (default: 10000, max: 30000)")),
                ("delayThresholdMs", SInt("Timing differential to flag as vulnerable in ms (default: 3000)")),
                ("teObfuscations", SBool("Test Transfer-Encoding header mutations (default: true)"))
            )),

        Tool("browser_security_host_header",
            "Host header injection scanner via raw TCP HTTP probing. Tests Host override, X-Forwarded-Host, " +
            "X-Original-Host, Forwarded, duplicate Host, port manipulation, and absolute-URL requests. Compares " +
            "poisoned responses against a baseline for reflected host values in redirects, links, and body text. " +
            "Useful for password-reset poisoning, cache poisoning, and open redirect via Host. Can auto-discover " +
            "reset/invite endpoints from the network log. Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("URL to test (default: current page, or use discoverFromNetwork)")),
                ("method", SStr("HTTP method (default: GET)")),
                ("body", SStr("Request body for POST probes (optional)")),
                ("json", new Dictionary<string, object> { ["type"] = "object", ["description"] = "JSON request body (optional; sets Content-Type: application/json)" }),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Extra request headers (optional)" }),
                ("evilHost", SStr("Marker host for injection probes (default: evil.trowser.test)")),
                ("probes", SArr("Probes: all (default), host-override, x-forwarded-host, x-original-host, forwarded, duplicate-host, host-port, absolute-url")),
                ("includeBrowserCookies", SBool("Send browser session cookies (default: true)")),
                ("discoverFromNetwork", SBool("Discover password-reset / invite URLs from network log")),
                ("maxTargets", SInt("Max URLs when discoverFromNetwork (default: 5)")),
                ("timeoutMs", SInt("Per-probe timeout ms (default: 15000)"))
            )),

        Tool("browser_security_waf_bypass",
            "WAF bypass technique probe. Sends a canonical attack payload (SQLi/XSS/LFI by default), detects whether " +
            "the WAF blocks it vs a benign baseline, then tests classic bypass transforms (URL encoding, double encoding, " +
            "mixed case, inline comments, whitespace/null-byte splits, X-Forwarded-For spoofing, path normalization, HPP, etc.). " +
            "Reports which techniques appear to reach the backend. Vendor fingerprinting is out of scope — use browser_security_tech_stack or wafw00f. " +
            "Requires safetyMode: active. Blocked in safe mode.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("URL template with §PAYLOAD§ marker, plain URL + paramName, or omit for current page")),
                ("method", SStr("HTTP method (default: GET)")),
                ("paramName", SStr("Query/body param name when url has no fuzz marker")),
                ("body", SStr("Request body template with §PAYLOAD§ marker (optional)")),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Extra request headers (optional)" }),
                ("category", SStr("Probe category: sqli (default), xss, lfi, custom — selects default probePayload")),
                ("probePayload", SStr("Canonical attack payload to test (overrides category default)")),
                ("baselineValue", SStr("Benign substitution value (default: 1)")),
                ("techniques", SArr("Subset of technique ids to run (default: all). Examples: url-encoding, double-url-encoding, xff-spoof, param-pollution")),
                ("timeout", SInt("Per-request timeout ms (default: 15000)")),
                ("useBackendFetch", SBool("Use server-side HttpClient instead of in-page fetch (default: false)")),
                ("includeBrowserCookies", SBool("Include browser session cookies when useBackendFetch (default: true)"))
            )),

        Tool("browser_validate_html",
            "Validate the current page's HTML markup using html-validate. " +
            "Checks for HTML syntax errors, content model violations, deprecated elements, " +
            "accessibility issues (WCAG), and document structure problems. " +
            "Returns errors and warnings grouped by category.",
            Schema()),

        Tool("browser_seo",
            "SEO audit of the current page from the live DOM. " +
            "Returns document title, meta description, robots, canonical URL, charset, viewport, html[lang], " +
            "H1 count, Open Graph (og:*) and Twitter Card (twitter:*) meta tags, hreflang alternates, " +
            "parsed JSON-LD blocks (script[type=application/ld+json]), plus critical issues and heuristic suggestions. " +
            "REST equivalent: POST /api/seo.",
            Schema()),

        Tool("browser_check_links",
            "Check all links on the current page for broken URLs, redirects, and errors. " +
            "Sends HEAD requests to each URL and reports status. " +
            "Redirects are reported as observations, not errors.",
            Schema(
                ("scope", SStr("What to check: 'anchors' (default, <a> tags only), 'resources' (images, scripts, stylesheets, iframes), 'all'")),
                ("external", SBool("Whether to check links to external domains (default: true)")),
                ("timeoutMs", SInt("Timeout per request in milliseconds (default: 5000)")),
                ("concurrency", SInt("Number of parallel requests (default: 10)")),
                ("delayMs", SInt("Delay between requests in milliseconds to avoid rate limiting (default: 100, 0 = no delay)"))
            )),

        Tool("browser_security_xss",
            "Audit the page's DOM for XSS-prone patterns. " +
            "Checks for inline event handlers (onclick etc.), javascript: URLs, " +
            "dangerous sinks (eval, document.write, innerHTML), cross-domain scripts without SRI, " +
            "data: URIs in iframes, external form actions, and base tag hijacking. " +
            "Inspired by OWASP ZAP passive scan rules.",
            Schema()),

        Tool("browser_mixed_content",
            "Check for mixed content on the current HTTPS page \u2014 HTTP resources that may be blocked by browsers. " +
            "Detects active mixed content (scripts, iframes \u2014 HIGH severity) and passive mixed content (images, stylesheets \u2014 MEDIUM). " +
            "Returns clean result on HTTP pages (not applicable).",
            Schema()),

        Tool("browser_security_cookies",
            "Audit cookies against OWASP best practices. " +
            "Reconciles cookie jar data with Set-Cookie headers from the network log (authoritative for HttpOnly/Secure/SameSite — avoids false positives when HttpOnly cookies are invisible to document.cookie). " +
            "Checks for: session cookies missing Secure flag, session/auth cookies missing HttpOnly (anti-CSRF/XSRF token cookies graded lower when HttpOnly is missing—often intentional for SPAs), " +
            "SameSite=None without Secure, overly broad domain scoping, and excessive cookie lifetimes. " +
            "Returns findings with severity/category/recommendation, plus an OWASP checklist with pass/fail per rule. " +
            "Included in browser_audit_all.",
            Schema()),

        Tool("browser_security_session_id",
            "Analyze session identifier cookies for weak entropy and predictable generation (sequential, timestamp-embedded, MD5-of-counter). " +
            "Collects samples from network Set-Cookie history; reports minSamplesMet. " +
            "Optional: cookieName, samples/extraSamples, minSamples (default 2), pageNetworkOnly.",
            Schema(
                ("cookieName", SStr("Session cookie name to analyze (default: all session-like cookies)")),
                ("samples", SArr("Additional session ID values to include in analysis")),
                ("minSamples", SInt("Minimum distinct samples for reliable predictability analysis (default 2)")),
                ("pageNetworkOnly", SBool("Only use network log entries since last navigation")))),

        Tool("browser_security_reset_token",
            "Analyze password-reset / verification tokens from network traffic for weak entropy and predictable patterns. " +
            "Collects tokens from reset/forgot-password URLs, JSON fields, query params, and Set-Cookie. " +
            "Optional: samples/extraSamples, minSamples (default 2), pageNetworkOnly. " +
            "REST: POST /api/security/reset-token.",
            Schema(
                ("samples", SArr("Additional reset token values to include in analysis")),
                ("minSamples", SInt("Minimum distinct samples for reliable predictability analysis (default 2)")),
                ("pageNetworkOnly", SBool("Only use network log entries since last navigation")))),

        Tool("browser_security_token_entropy",
            "Generic security token entropy analysis (CSRF nonces, OAuth state/nonce, custom params). " +
            "Collects samples from query params, headers, cookies, JSON/form bodies, and DOM hidden inputs. " +
            "Use presets: csrf, oauth-state, oauth-nonce, anti-forgery — or paramName/source for a single target. " +
            "autoDiscover (default when no target): scan known token names in traffic. " +
            "REST: POST /api/security/token-entropy.",
            Schema(
                ("name", SStr("Display label for single-target mode")),
                ("paramName", SStr("Parameter/cookie/header/field name to analyze")),
                ("source", SStr("query | header | cookie | json | form | dom | auto (default auto)")),
                ("targets", SArr("Explicit targets: [{ name, paramName, source }]")),
                ("presets", SArr("Built-in profiles: csrf, oauth-state, oauth-nonce, anti-forgery")),
                ("autoDiscover", SBool("Scan known CSRF/OAuth token names when no explicit target (default true)")),
                ("samples", SArr("Additional token values to include in analysis")),
                ("minSamples", SInt("Minimum distinct samples per target (default 2)")),
                ("pageNetworkOnly", SBool("Only use network log entries since last navigation")),
                ("includeDom", SBool("Include hidden input values from current page (default true)")))),

        Tool("browser_security_storage",
            "Audit localStorage and sessionStorage for security issues. " +
            "Detects: auth tokens/JWTs stored client-side, PII (emails, SSNs, phone numbers), " +
            "HTML/script content that could be a stored XSS vector, and credentials/secrets. " +
            "Flags localStorage tokens as high severity (persists across sessions, XSS-accessible). " +
            "Returns findings with severity, category, and remediation advice.",
            Schema()),

        Tool("browser_security_source_maps",
            "Scan the current page for source map exposure and framework debug mode indicators. " +
            "Detects sourceMappingURL directives in HTML/JS/CSS, probes for accessible .map files " +
            "(information disclosure — original source code), and checks for debug globals " +
            "(Angular ng.probe, React DevTools hook, Vue DevTools hook, Redux DevTools). " +
            "Source maps in production are a HIGH-severity finding; debug indicators are LOW.",
            Schema()),

        Tool("browser_security_tech_stack",
            "Detect the technology stack of the current page: web servers, frameworks, programming languages, " +
            "JavaScript libraries/frameworks, WAFs, CDNs, CMSes, and analytics. " +
            "Combines HTTP response headers, cookies, DOM patterns (meta tags, data attributes, global JS objects), " +
            "and script URL analysis. Useful for reconnaissance — knowing the stack guides which fuzz payloads, " +
            "CVE databases, and attack vectors to prioritize. WAF detection warns when payloads may be filtered. " +
            "No parameters needed.",
            Schema()),

        Tool("browser_security_js_audit",
            "Fetch external script[src] bundles from the current DOM and run heuristic scans for hardcoded credentials, " +
            "internal/private URLs, and debug/test markers (complements source-maps). Uses server-side HTTP. " +
            "REST: POST /api/security/js-audit. Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("maxScripts", SInt("Max distinct script URLs to fetch (default 32, max 80)")),
                ("maxBytesPerFile", SInt("Max bytes read per file (default 524288)")),
                ("sameOriginOnly", SBool("Only script URLs on the same host as the page (default false)")),
                ("timeoutMs", SInt("Per-request HTTP timeout (default 20000)"))
            )),

        Tool("browser_security_nuclei_scan",
            "Run curated nuclei HTTP templates (embedded subset and/or your own) against one or more target URLs. Supports " +
            "status/word/regex/header matchers with {{BaseURL}}/{{RootURL}} substitution. Read-only GET/HEAD templates run " +
            "under safetyMode safe; templates with write verbs require active. Load custom templates via templatesDir (or the " +
            "TROWSER_NUCLEI_TEMPLATES env var / a nuclei-templates/ folder beside the exe). REST: POST /api/security/nuclei-scan.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe (GET/HEAD templates) | active | aggressive. Default: safe")),
                ("targetUrl", SStr("Target base URL (default: current page URL)")),
                ("targetUrls", SArr("Optional list of base URLs to scan (merged with targetUrl, deduped)")),
                ("tags", SArr("Optional tag filter — array of tags, or a comma-separated string; runs templates matching any tag")),
                ("severity", SStr("Minimum template severity to include: info | low | medium | high | critical (alias: minSeverity)")),
                ("minSeverity", SStr("Alias of severity (minimum template severity)")),
                ("maxTemplates", SInt("Max templates to run (default 50)")),
                ("timeoutMs", SInt("Per-request HTTP timeout in ms (default 10000)")),
                ("templatesDir", SStr("Optional directory of user *.yaml/*.yml templates to include")),
                ("includeBuiltinTemplates", SBool("Include the embedded template subset (default true; set false to run only templatesDir)")),
                ("followRedirects", SBool("Follow HTTP redirects (default false so redirect/Location matchers work)")),
                ("dryRun", SBool("Resolve/select templates and return selectedTemplateIds without sending HTTP (default false)")),
                ("verboseTemplateTrace", SBool("Return a per-template URL/status/matcher-pass trace (default false)")),
                ("registerChainFindings", SBool("Register matches as chain findings (default true)"))
            )),

        Tool("browser_security_nuclei_templates",
            "List the runnable nuclei templates (embedded subset and/or a user templatesDir) without scanning: " +
            "id, name, severity, tags, methods, source, plus a tag catalog and any skipped/unsupported templates. " +
            "REST: GET /api/security/nuclei-templates.",
            Schema(
                ("templatesDir", SStr("Optional directory of user *.yaml/*.yml templates to include")),
                ("includeBuiltinTemplates", SBool("Include the embedded template subset (default true)"))
            )),

        Tool("browser_saml_decode",
            "Decode SAMLRequest/SAMLResponse from network log or raw input (Redirect/POST bindings) with security checks " +
            "(signatures, algorithms, expiry, audience). source:'network'|'raw'; findAll for every match.",
            Schema(
                ("source", SStr("'network' to search network log (default), or 'raw' to decode a provided value")),
                ("networkFilter", SStr("URL substring filter when source='network' (e.g. 'SAMLRequest', 'sso')")),
                ("raw", SStr("Raw SAML parameter value when source='raw'")),
                ("encoding", SStr("'redirect' for HTTP-Redirect binding (URL+Base64+DEFLATE), 'post' for HTTP-POST binding (Base64). Default: 'redirect'")),
                ("findAll", SBool("Return ALL SAML messages from network log (not just the most recent). Default: false"))
            )),

        Tool("browser_saml_capture",
            "Capture SAML assertions during SSO login flows. Four modes: " +
            "'next-login' arms the capture to automatically intercept the next SAMLResponse POST " +
            "(navigate through the IdP, then call with mode='status' or GET to retrieve). " +
            "Set captureRequests=true to also capture the outgoing SAMLRequest for comparison. " +
            "'network' searches existing network log entries for SAML responses. " +
            "'status' checks capture status and returns captured data. " +
            "'disarm' cancels an armed capture. " +
            "After capture, use browser_saml_replay to test assertion replay, " +
            "signature removal, identity spoofing, and time-window attacks.",
            Schema(
                ("mode", SStr("'next-login' to arm capture (default), 'network' to search existing log, 'disarm' to cancel, 'status' to check")),
                ("url", SStr("URL filter when mode='network'")),
                ("captureRequests", SBool("Also capture outgoing SAMLRequest when mode='next-login'. Enables comparing what the SP sent vs what the IdP returned"))
            )),

        Tool("browser_saml_replay",
            "Replay a captured SAML assertion with modifications for security testing. " +
            "Tests critical SAML vulnerabilities: signature removal (CVE-2025-47949, CVE-2025-25291/25292), " +
            "identity spoofing (NameID manipulation), assertion replay (expired assertion acceptance), " +
            "audience restriction bypass, and issuer spoofing. " +
            "Requires a previously captured assertion (browser_saml_capture) or a raw assertion XML/Base64. " +
            "Use customXml for arbitrary XML modifications not covered by built-in options. " +
            "Use dryRun=true to preview modifications without sending. " +
            "Returns structured response including HTTP status code. " +
            "**Requires safetyMode: active** — sends modified assertions to the SP.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required for replay) | aggressive. Default: safe")),
                ("targetUrl", SStr("SP assertion consumer service URL (defaults to captured URL)")),
                ("assertion", SStr("Raw assertion XML or Base64 (optional — uses captured assertion if omitted)")),
                ("removeSignature", SBool("Remove XML signatures to test unsigned assertion acceptance")),
                ("changeSubject", SStr("Change NameID value to test identity spoofing")),
                ("expireAssertion", SBool("Set NotOnOrAfter to past time to test expired assertion acceptance")),
                ("extendValidityMinutes", SInt("Extend assertion validity window by N minutes")),
                ("removeAudienceRestriction", SBool("Remove AudienceRestriction to test cross-SP replay")),
                ("changeIssuer", SStr("Change Issuer value to test issuer validation")),
                ("customXml", SStr("Full custom XML assertion to send instead of using built-in modifications")),
                ("dryRun", SBool("Preview modifications without sending the replay request"))
            )),

        Tool("browser_structured_text",
            "Extract all text content from the page in a structured format for proofreading. " +
            "Returns headings (with hierarchy), paragraphs, link texts with URLs, button labels, " +
            "form labels, image alt texts, meta description, language, word count, and full text. " +
            "Much more useful than raw innerText for text review and spell-checking.",
            Schema()),

        Tool("browser_consistency",
            "Audit the page's visual consistency. Analyzes computed styles to count distinct " +
            "font families, font sizes, text colors, background colors, button heights, input heights, " +
            "and spacing values. Warns when counts exceed thresholds indicating design inconsistency. " +
            "Useful for design system compliance checks.",
            Schema()),

        Tool("browser_third_party",
            "Inventory all third-party resources loaded by the page (external scripts, stylesheets, iframes, fonts). " +
            "Shows domains, transfer sizes, and Subresource Integrity (SRI) coverage. " +
            "Missing SRI is labelled low/informative in the report (common in production; still useful defense-in-depth where you can add it). " +
            "Useful for privacy audits, GDPR awareness, and supply chain review.",
            Schema()),

        Tool("browser_compatibility",
            "Analyze the page's JavaScript for backward compatibility with older browsers. " +
            "Downloads and scans all scripts (inline and external) for modern ES2020+ syntax features " +
            "(optional chaining, nullish coalescing, private fields, etc.) and newer Web APIs " +
            "(structuredClone, Object.hasOwn, Array.at, etc.). " +
            "Reports which features would break on target browsers. Defaults to iOS 15 and Android 10. " +
            "Syntax features cause complete script failure; API features cause runtime errors. " +
            "Returns a risk assessment with testing recommendations.",
            Schema(
                ("minIos", SInt("Minimum iOS version to support (e.g. 15, 16). Maps to Safari version.")),
                ("minAndroid", SInt("Minimum Android version to support (e.g. 9, 10). Maps to Chrome WebView version."))
            )),

        Tool("browser_audit_all",
            "Full page health audit in one call (a11y, Web Vitals, security, headers, HTML, SEO, compatibility, links, consistency, secrets). " +
            "safetyMode: active enables JS bundle + source-map harvest. REST: POST /api/audit-all.",
            Schema(
                ("includeSecretsHarvest", SBool("Run secrets harvest pass (default true)")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (enables JS bundle + source-map harvest) | aggressive. Default: safe")),
                ("maxBytesPerFile", SInt("Max bytes per JS bundle in audit-all secrets pass (default 524288)")),
                ("level", SStr("WCAG level for accessibility (default AA)")),
                ("selector", SStr("CSS selector to scope accessibility audit")),
                ("minIos", SInt("Minimum iOS version for compatibility audit")),
                ("minAndroid", SInt("Minimum Android version for compatibility audit")),
                ("scope", SStr("Link check: anchors, resources, or all (default anchors)")),
                ("external", SBool("Link check: include external URLs (default true)")),
                ("timeoutMs", SInt("Link check timeout per request (default 5000)")),
                ("concurrency", SInt("Link check parallel requests (default 10)")),
                ("delayMs", SInt("Link check delay between requests ms (default 100)")),
                ("includeProtocolLayer", SBool("Include A14 protocol-layer rollup: open redirect, smuggling risk, cache, websocket (default true)")),
                ("includeApiInventory", SBool("OpenAPI vs traffic API inventory block (default true; can be slow — use apiInventoryMaxSeconds)")),
                ("apiInventoryMaxSeconds", SInt("Wall-clock cap for API inventory enrichment in audit-all (default 90)"))
            )),

        Tool("browser_surpriseme",
            "Run a random non-destructive quicktest from the embedded Quicktests catalog (same as REST POST /api/surpriseme). " +
            "Picks a category-balanced test that may surface issues you had not thought to check. " +
            "Returns JSON with quicktest name, success, assertion summary, and elapsedMs.",
            Schema()),

        Tool("browser_monkey_test",
            "Run a monkey test (gremlins.js) that performs random user actions to test page robustness. " +
            "Gremlins click, type, fill forms, scroll, and touch randomly. " +
            "Returns errors found, FPS drops, and whether the page survived. " +
            "Use the seed from results to reproduce failures. " +
            "WARNING: This test interacts with the live page and may trigger real server-side actions " +
            "(form submissions, deletions, purchases). Requires safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("actions", SInt("Number of random actions (default 500)")),
                ("delay", SInt("Milliseconds between actions (default 20)")),
                ("seed", SInt("Random seed for reproducibility")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe"))
            )),

        Tool("browser_monkey_trowser",
            "Monkey Trowser: systematic robustness — click interactives, fuzz forms, crawl in-scope links with attribution. " +
            "Uses Settings/--scope/scope body when set; otherwise temporary scope from the current page registrable domain. safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("followLinks", SBool("Follow links to other pages within scope (default true)")),
                ("fuzzForms", SBool("Fuzz form inputs with edge-case data (default true)")),
                ("maxPages", SInt("Maximum pages to visit when crawling (default 10)")),
                ("maxActionsPerPage", SInt("Maximum element interactions per page (default 100)")),
                ("scope", SStr("Optional. Navigation scope for this run only (e.g. https://*.example.com). Same format as Settings; overrides auto-scope from current page.")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe"))
            )),

        Tool("browser_interrupter",
            "Fault-injection: discover/rank APIs from network log, mock faults, reload, check failures. " +
            "Presets via faults[]; see properties for discovery/replay knobs. Reloads page — safetyMode: active.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("url", SStr("Target a specific URL (bypasses auto-discovery — works even if URL is not in network log). Omit to auto-discover.")),
                ("method", SStr("Filter endpoints by HTTP method (e.g. GET, POST). Omit for all methods.")),
                ("faults", SArr("Subset of fault preset names: server-error, not-found, empty-body, invalid-json, slow-response, unauthorized, forbidden, rate-limited, mutate-response. Omit for default 5.")),
                ("maxEndpoints", SInt("Maximum endpoints to test when auto-discovering (default 20). Endpoints ranked by relevance score.")),
                ("minRelevanceScore", SInt("Minimum relevance score 0-100 (default 0). Alias: minScore. Raise to trim low-ranked candidates when discovery is too broad.")),
                ("mergeAttackSurface", SBool("Merge endpoints from attack-surface analysis of the network log (default true). Set false to use only raw log entries.")),
                ("waitForIdle", SBool("Wait for network idle before reading the network log for discovery (default false). Useful immediately after navigation.")),
                ("allowedHosts", SArr("Additional hosts to include in auto-discovery besides the current page's origin. By default only same-origin endpoints are discovered.")),
                ("cooldownMs", SInt("Delay in ms between scenarios to avoid rate limits (default 0 = no delay).")),
                ("customFaults", SObjArr("Custom fault definitions: [{name, status, body?, headers?, delayMs?}]. Tested alongside selected presets.")),
                ("actions", SObjArr("Actions to replay after each page reload, for user-triggered endpoints. " +
                    "Same targeting as batch API: [{action: 'click'|'type'|'select'|'hover'|'press_key'|'wait', " +
                    "byText/placeholder/selector/role/name/label/testId, text?, value?, key?, delayMs?}].")),
                ("restoreUrl", SBool("Navigate back to the original URL after testing and detect login redirects (default true).")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe"))
            )),

        Tool("browser_attack_form",
            "Probe a live form for client-side validation gaps (type-aware payloads; default does not submit). " +
            "submit:true also replays server-side (mutates state; safetyMode: active). REST: POST /api/attack-form.",
            Schema(
                ("target", SStr("CSS selector or semantic locator (@role:/@label:/@text:/@testid:) for a form, submit button, or any field in the form. Omit to auto-pick the page's primary form.")),
                ("submit", SBool("Also replay the form server-side with attack payloads (default false). Mutates server state; requires safetyMode: active.")),
                ("maxFields", SInt("Maximum fields to probe (default 15).")),
                ("perField", SInt("Maximum payloads per field (default 18).")),
                ("safetyMode", SStr("Safety mode: passive | safe | active | aggressive. Only required when submit=true."))
            )),

        Tool("browser_fuzz",
            "Browser-context request fuzzer (Intruder-style): §MARKER§/{{MARKER}} templates, payload sets, " +
            "sniper/battering-ram/pitchfork/cluster-bomb. Uses session cookies. Requires safetyMode: active. See properties for sets/flags.",
            Schema(
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe")),
                ("request", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Request template with §MARKER§ or {{MARKER}} injection points. Properties: url (required), method (supports markers for HTTP method fuzzing), headers (object), body (string) or json (object).",
                    ["properties"] = new Dictionary<string, object>
                    {
                        ["url"] = SStr("Target URL with optional §MARKER§ or {{MARKER}} injection points"),
                        ["method"] = SStr("HTTP method (default GET). Supports markers for method fuzzing."),
                        ["headers"] = new Dictionary<string, object> { ["type"] = "object", ["description"] = "Request headers (string values, may contain §MARKER§ or {{MARKER}})" },
                        ["body"] = SStr("Request body string (may contain §MARKER§ or {{MARKER}})"),
                        ["json"] = new Dictionary<string, object> { ["type"] = "object", ["description"] = "JSON body (alternative to body, may contain markers in string values)" }
                    }
                }),
                ("injectionPoints", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional map of injection point names to config. Key = marker name (without § or {{}}). " +
                        "Value = {payloadSet: 'name'}. Example: {\"PAYLOAD\": {\"payloadSet\": \"sqli-basic\"}}. " +
                        "When omitted, markers in request.url/body/headers are auto-detected (default payloadSet: first custom set or sqli-basic)."
                }),
                ("payloadSets", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Custom payload sets. Key = set name. Value = array of payload strings, " +
                        "or [\"built-in\"] to use the built-in set with that name."
                }),
                ("payloadGenerators", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Payload generators for programmatic payload creation. Key = set name to extend. " +
                        "Value = array of generator objects. Types: " +
                        "range {type:'range', from:0, to:255, step:1}, " +
                        "pattern {type:'pattern', template:'user{N}@test.com', from:1, to:100}, " +
                        "combine {type:'combine', baseSet:'xss-basic', encodings:['url-encode','base64','html-entity','unicode','hex','double-url-encode']}."
                }),
                ("attackType", SStr("Attack strategy: sniper (default), battering-ram, pitchfork, cluster-bomb.")),
                ("maxConcurrency", SInt("Maximum concurrent requests (default 5, max 20).")),
                ("useBrowserCookies", SBool("Use browser cookies and session state (default true).")),
                ("stopOnStatus", SArr("Stop fuzzing when any of these status codes are encountered.")),
                ("acceptableResponseStatuses", SArr("HTTP statuses that do not count as status/length anomalies vs baseline (e.g. 400, 403, 412). 5xx, reflection, and error-pattern flags are unchanged.")),
                ("maxRequests", SInt("Maximum total requests to send (default 1000, safety cap).")),
                ("availabilitySafeDefaults", SBool("A12-safe fuzz caps: maxRequests=50, maxConcurrency=3, delayMs=100 unless overridden")),
                ("timeoutMs", SInt("Timeout per request in ms (default 10000).")),
                ("delayMs", SInt("Delay between request batches in ms (default 0).")),
                ("bodySnippetLength", SInt("Max body snippet length in results (default 500, 0 to exclude).")),
                ("maxResponseBodyLength", SInt("Max response body chars per result for /api/fuzz JSON (default 131072, 0 to omit body field).")),
                ("redirect", SStr("Fetch redirect mode: follow (default) or manual — use manual to capture Location on 302 without following off-site redirects")),
                ("payloadProfile", SStr("Payload corpus breadth for built-in payload sets: small (default) | big")),
                ("safetyMode", SStr("Safety mode: passive | safe | active (required) | aggressive. Default: safe"))
            ),
            required: ["request"]),

        Tool("browser_property",
            "Read a live DOM property (value, checked, selectedIndex, disabled, …) — not snapshot attributes. Target with ref or locator.",
            ElementSchema(("property", SStr("DOM property name: value, checked, selectedIndex, disabled, etc."))),
            required: ["property"]),

        Tool("browser_console",
            "Get browser console messages (logs, warnings, errors). Optional tabIndex reads another tab without switching.",
            Schema(
                ("tabIndex", SInt("0-based tab index (default: active tab)"))
            )),

        Tool("browser_console_clear",
            "Clear all captured console messages. Use between test sections to isolate errors " +
            "to specific page loads or actions.",
            Schema()),

        Tool("browser_network",
            "Network traffic log with filters (url/method/status/type/id). summary:true for compact all-matching view; " +
            "detailed mode returns most recent limit entries. Pass id for one entry with headers and the captured body. " +
            "includeHeaders/includeBody for evidence on a list.",
            Schema(
                ("errorsOnly", SBool("Only return failed/error requests")),
                ("url", SStr("Filter by URL substring")),
                ("method", SStr("Filter by HTTP method (GET, POST, etc.)")),
                ("id", SInt("One log entry by id (from a previous network listing). Includes headers and the captured body unless turned off.")),
                ("status", SInt("Filter by exact HTTP status code")),
                ("statusMin", SInt("Inclusive min status when filtering by range (use with statusMax)")),
                ("statusMax", SInt("Inclusive max status when filtering by range (use with statusMin)")),
                ("type", SStr("Filter by resource type (Document, Fetch, XHR, Script, Stylesheet, Image, etc.)")),
                ("includeDataUrls", SBool("Include data: URLs (default false — they blow agent context)")),
                ("maxUrlChars", SInt("Truncate URL display length (default 500)")),
                ("includeHeaders", SBool("Include full request and response HTTP headers for each entry (max 12 per side in detailed mode)")),
                ("includeBody", SBool("Include truncated response/request body previews in detailed mode")),
                ("bodyMaxChars", SInt("Max body chars per entry when includeBody is true (default 200, 0 = full body)")),
                ("summary", SBool("One-line-per-request compact view for all matching entries (method, status, url, duration, cache, bodyLen)")),
                ("limit", SInt("Max entries in detailed mode (default 50, most recent shown)")),
                ("tabIndex", SInt("0-based tab index (default: active tab; restores prior active tab after the call)"))
            )),

        Tool("browser_network_clear",
            "Clear the network traffic log. Call this after reviewing network data to free memory, " +
            "especially after pages with heavy traffic. Similar to browser_console_clear.",
            Schema()),

        Tool("browser_network_har",
            "Export the network log as HAR 1.2 JSON (from the in-memory NetworkLog). " +
            "Optional filters mirror browser_network. Bodies truncated to capture caps; includeBodies defaults false.",
            Schema(
                ("includeHeaders", SBool("Include request/response headers (default true)")),
                ("includeBodies", SBool("Include captured request/response bodies (default false)")),
                ("url", SStr("Filter by URL substring")),
                ("method", SStr("Filter by HTTP method")),
                ("errorsOnly", SBool("Only error responses")),
                ("pageOnly", SBool("Only entries since last navigation"))
            )),

        Tool("browser_downloads",
            "List captured browser downloads (id, url, suggestedFileName, path, state, bytes, mime).",
            Schema()),

        Tool("browser_wait_for_download",
            "Wait until a matching download reaches completed and the saved file exists on disk (not merely started).",
            Schema(
                ("fileNameContains", SStr("Substring match on suggested file name")),
                ("timeout", SInt("Timeout in ms (default 30000)")),
                ("afterId", SInt("Only match downloads with id greater than this"))
            )),

        Tool("browser_assert_download",
            "Assert a captured download is completed with expected filename/mime/minBytes/file exists. Records into /api/assertions.",
            Schema(
                ("fileNameContains", SStr("Expected filename substring")),
                ("mime", SStr("Expected mime substring")),
                ("minBytes", SInt("Minimum bytes received")),
                ("exists", SBool("Whether the saved file must exist (default true)"))
            )),

        Tool("browser_clear_all",
            "Reset all test session state in one call. Clears: console log, network log, cookies, " +
            "mock rules, intercept rules, assertion counters, network throttle, viewport override, " +
            "and web storage (localStorage + sessionStorage). " +
            "Use between test sessions or to recover from leftover state after interrupted tests. " +
            "Pass 'preserve' to keep specific categories intact (e.g. [\"cookies\",\"storage\"] to avoid destroying session).",
            Schema(
                ("preserve", new Dictionary<string, object>
                {
                    ["type"] = "array",
                    ["items"] = new Dictionary<string, object> { ["type"] = "string" },
                    ["description"] = "Categories to keep: cookies, storage, mocks, intercepts, throttle, viewport"
                })
            )),

        Tool("browser_clear_session",
            "Lighter reset — clears test artifacts (console, network, assertions, mocks, intercepts, " +
            "throttle, viewport) but preserves cookies and web storage by default. " +
            "Set clearCookies:true to also wipe the cookie jar (useful when switching lab apps on the same host).",
            Schema(
                ("clearCookies", SBool("Also clear all cookies (default false). Use when switching apps on localhost."))
            )),

        Tool("browser_wait",
            "Wait for an element (ref preferred, or selector/semantic locator). state: visible (default), attached, or hidden. Returns found/timeout within timeout ms.",
            ElementSchema(
                ("timeout", SInt("Max wait in milliseconds (default: 10000)")),
                ("state", SStr("visible | attached | hidden (default: visible)")))),

        Tool("browser_wait_for_final_navigation",
            "Wait for a navigation chain to settle (redirects, SSO, auto-submit). quietPeriod ms of no new navigations before return.",
            Schema(
                ("quietPeriod", SInt("Milliseconds of quiet after last navigation to consider settled (default: 500)")),
                ("timeout", SInt("Maximum total wait in milliseconds (default: 15000)"))
            )),

        Tool("browser_wait_for_idle",
            "Wait until the network is quiet and CSS animations have stopped (same as POST /api/wait-for-idle). " +
            "Useful after clicks/navigation that trigger XHR/fetch bursts or animated UI transitions.",
            Schema(
                ("quietPeriod", SInt("Milliseconds of quiet network/animation activity required (default: 500)")),
                ("timeout", SInt("Maximum total wait in milliseconds (default: 10000)"))
            )),

        Tool("browser_assert_text",
            "Assert that the page contains (or does not contain) specific text. Results are tracked in an assertion summary.",
            Schema(
                ("text", SStr("The text to search for on the page")),
                ("shouldNotContain", SBool("If true, assert the text is NOT present")),
                ("message", SStr("Description for the assertion result"))
            ),
            required: ["text"]),

        Tool("browser_assert_element",
            "Assert one of: visible, hasText, containsText, attribute(+expected), or count. Target with ref (preferred) or locator.",
            ElementSchema(
                ("visible", SBool("Assert element visibility (true = visible, false = hidden)")),
                ("hasText", SStr("Assert element inner text equals this")),
                ("containsText", SStr("Assert element text contains this substring")),
                ("attribute", SStr("Attribute name to check (combine with 'expected')")),
                ("expected", SStr("Expected value (for attribute or count assertions)")),
                ("count", SInt("Assert number of matching elements")),
                ("message", SStr("Custom assertion description"))
            )),

        Tool("browser_assert_url",
            "Assert that the current URL contains the expected substring.",
            Schema(
                ("expected", SStr("Expected URL substring")),
                ("message", SStr("Custom assertion description"))
            ),
            required: ["expected"]),

        Tool("browser_assert_title",
            "Assert that the current page title contains the expected value (case-insensitive).",
            Schema(
                ("expected", SStr("Expected text to find in the page title")),
                ("message", SStr("Custom assertion description"))
            ),
            required: ["expected"]),

        Tool("browser_tabs",
            "List all open browser tabs with their index, title, URL, owner (human/agent/shared), and which one is active. " +
            "Use this to see what tabs are open before switching or closing.",
            Schema()),

        Tool("browser_new_tab",
            "Open a new browser tab. Optionally navigate it to a URL. " +
            "The new tab becomes the active tab and is agent-owned by default so it does not hijack the tester's page. Returns the tab index.",
            Schema(
                ("url", SStr("URL to navigate the new tab to (optional — opens welcome page if omitted)")),
                ("owner", SStr("Tab owner: human, agent (default for this tool), or shared"))
            )),

        Tool("browser_close_tab",
            "Close a browser tab by index. If no index is given, closes the active tab. " +
            "Cannot close the last remaining tab.",
            Schema(
                ("tabIndex", SInt("Index of the tab to close (optional — closes active tab if omitted)"))
            )),

        Tool("browser_switch_tab",
            "Switch the active browser tab. All subsequent browser actions will target this tab.",
            Schema(
                ("tabIndex", SInt("Index of the tab to switch to (0-based)"))
            ),
            required: ["tabIndex"]),

        Tool("browser_viewport",
            "Set the browser viewport size for responsive design testing. " +
            "Use exact pixel dimensions or a preset: SmallPhone (320×568), BigPhone (412×915), LandscapePhone (844×390)," +
            "SmallPad (768×1024), BigPad (1024×1366), Desktop (full screen), BigDesktop (1920×1080). " +
            "Only the page rendering viewport changes — the Trowser window stays the same. " +
            "Media queries, CSS breakpoints, and layout all respond to the new viewport size. " +
            "Related but separate: browser_emulation for geo/locale/timezone/UA; browser_network_throttle for bandwidth.",
            Schema(
                ("width", SInt("Viewport width in pixels")),
                ("height", SInt("Viewport height in pixels")),
                ("preset", SStr("Device preset: SmallPhone, BigPhone, LandscapePhone, SmallPad, BigPad, Desktop, BigDesktop"))
            )),

        Tool("browser_emulation",
            "Get or set environment overrides (geolocation, locale, timezone, colorScheme, reducedMotion, userAgent, permissions). " +
            "action: get (default) | set | clear. Cleared by browser_clear_session / clear-all.",
            Schema(
                ("action", SStr("get | set | clear")),
                ("geolocation", SObj("{latitude, longitude, accuracy?} or {clear:true}")),
                ("locale", SStr("BCP-47 locale, e.g. sv-SE; empty string clears")),
                ("timezone", SStr("IANA timezone, e.g. Europe/Stockholm; empty string clears")),
                ("colorScheme", SStr("light | dark | no-preference")),
                ("reducedMotion", SStr("reduce | no-preference")),
                ("userAgent", SStr("Override UA string; empty string clears")),
                ("permissions", SObj("Map of permission name → granted|denied|prompt"))
            )),

        Tool("browser_trace",
            "Start/stop/export an action timeline (ordered automation steps). Not a Playwright .zip trace viewer. " +
            "action: start | stop | get | export. Optional domSnapshots (default false), maxSteps (default 200).",
            Schema(
                ("action", SStr("start | stop | get | export")),
                ("domSnapshots", SBool("Store compact DOM snapshot ids per step (default false)")),
                ("maxSteps", SInt("Ring buffer size (default 200)"))
            )),

        Tool("browser_webmcp_tools",
            "Detect and list WebMCP tools registered on the current page via navigator.modelContext. " +
            "Web applications can expose structured tools (add_to_cart, search, etc.) that AI agents can discover and call " +
            "instead of manipulating DOM elements. Returns each tool's name, description, and input schema.",
            Schema()),

        Tool("browser_webmcp_call",
            "Call a WebMCP tool registered on the current page. The tool's execute function is invoked with the given arguments. " +
            "Use browser_webmcp_tools first to discover available tools and their input schemas.",
            Schema(
                ("tool", SStr("Name of the WebMCP tool to call")),
                ("arguments", new Dictionary<string, object> {
                    ["type"] = "object",
                    ["description"] = "Arguments to pass to the tool (must match the tool's inputSchema)",
                    ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" }
                })
            ),
            required: ["tool"]),

        Tool("browser_handle_dialog",
            "Configure how native browser dialogs (alert, confirm, prompt) are handled. " +
            "By default, dialogs are auto-accepted. Call BEFORE the action that triggers the dialog. " +
            "Use accept: false to dismiss (click Cancel). For prompt dialogs, use promptText to set the response. " +
            "Use browser_dialog to check the last dialog that appeared.",
            Schema(
                ("accept", SBool("Accept (true) or dismiss (false) the dialog. Default: true")),
                ("promptText", SStr("Text to enter in prompt dialogs"))
            )),

        Tool("browser_dialog",
            "Get the most recent native dialog (alert, confirm, prompt) that appeared. " +
            "Returns the dialog type, message, and default value (for prompts). Returns null if no dialog appeared.",
            Schema()),

        Tool("browser_run_script",
            "Execute a C# (.csx) automation script with full Trowser API access (Navigate/Click/Assert.* — not MCP JSON). " +
            "Prefer one script over many tool calls for repeatable checks. Call browser_scripting_help first for the API cheat sheet. " +
            "Laws: declare with Site(...); Law(\"name\").OnPage(\"/path*\").Expect(p => ...); then await CheckLaws() (this run only) or CheckLaws(allLoaded: true). " +
            "Persist Laws with browser_laws action add, not inline in long-lived scripts.",
            Schema(("code", SStr("C# test script code to execute"))),
            required: ["code"]),

        Tool("browser_record_start",
            "Start interaction recording. Captures human DOM actions (clicks, typing) into a .csx script — not MCP/REST tool calls. " +
            "409-equivalent error if already recording. Pair with browser_record_stop after the user interacts.",
            Schema()),

        Tool("browser_record_status",
            "Whether interaction recording is active, plus startUrl, startedAt, and actionCount.",
            Schema()),

        Tool("browser_record_stop",
            "Stop interaction recording and return the .csx script and narration. " +
            "Optional: description, toJournal (embed script for Journal Show me), path (write .csx via ExportPathGuard; blocked in --safe). " +
            "Does not open Script Console or AI chat — the response is the handoff.",
            Schema(
                ("description", SStr("Optional label for the recording / journal summary")),
                ("toJournal", SBool("When true, add a journal recording entry with embedded csx")),
                ("path", SStr("Optional absolute .csx path to write (alias: toFile). Blocked in --safe."))
            )),

        Tool("browser_mock",
            "Manage network mock rules (fault injection without hitting the server). Actions: add, list, remove, clear. See properties for fields.",
            Schema(
                ("action", SStr("Action: add, list, remove, clear")),
                ("urlPattern", SStr("URL pattern (glob wildcards * or plain substring). Required for add/remove.")),
                ("status", SInt("HTTP status code for mock response (default 200)")),
                ("body", SStr("Response body string")),
                ("method", SStr("HTTP method filter (null = any)")),
                ("headers", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Response headers as key-value pairs",
                    ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" }
                }),
                ("delay", SInt("Artificial delay in ms before responding"))
            ),
            required: ["action"]),

        Tool("browser_intercept",
            "Manage network breakpoints (pause/continue/fulfill/abort held requests). Actions: add, list, remove, clear, continue, fulfill, abort.",
            Schema(
                ("action", SStr("Action: add, list, remove, clear, continue, fulfill, abort")),
                ("urlPattern", SStr("URL regex pattern. Required for add/remove.")),
                ("method", SStr("HTTP method filter (for add) or modified method (for continue)")),
                ("requestId", SInt("ID of the pending request (for continue/fulfill/abort)")),
                ("url", SStr("Modified URL (for continue only)")),
                ("status", SInt("HTTP status code (for fulfill, default 200)")),
                ("body", SStr("Response body (for fulfill)")),
                ("headers", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Response headers (fulfill) or modified request headers (continue)",
                    ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" }
                })
            ),
            required: ["action"]),

        Tool("browser_network_throttle",
            "Simulate slow network conditions (2G, 3G, 4G, offline) for performance testing. " +
            "Tests how the page handles slow connections: loading spinners, timeouts, perceived performance.\n\n" +
            "Actions:\n" +
            "  set   - Enable throttling: preset (2G, Slow3G, 3G, 4G, Offline) or custom (downloadKbps, uploadKbps, latencyMs)\n" +
            "  get   - Get current throttle state and available presets\n" +
            "  clear - Disable throttling and restore full speed",
            Schema(
                ("action", SStr("Action: set, get, clear")),
                ("preset", SStr("Network preset: 2G, Slow3G, 3G, 4G, Offline")),
                ("downloadKbps", SInt("Download speed in KB/s (custom throttle)")),
                ("uploadKbps", SInt("Upload speed in KB/s (custom throttle)")),
                ("latencyMs", SInt("Network latency in milliseconds (custom throttle)")),
                ("offline", SBool("Simulate offline (no connectivity)"))
            ),
            required: ["action"]),

        Tool("browser_wait_for_network",
            "Wait for a specific network request to complete. Matches by URL substring, " +
            "optionally filtered by HTTP method and status code. " +
            "Use instead of arbitrary waits when you need to wait for a specific API call to finish.",
            Schema(
                ("urlPattern", SStr("URL substring to match (case-insensitive)")),
                ("method", SStr("HTTP method filter (GET, POST, etc.)")),
                ("status", SInt("Expected HTTP status code")),
                ("timeout", SInt("Max wait in milliseconds (default: 10000)"))
            ),
            required: ["urlPattern"]),

        Tool("browser_storage",
            "Read and write browser localStorage and sessionStorage. " +
            "Many SPAs store auth tokens, user preferences, and feature flags here.\n\n" +
            "Actions:\n" +
            "  get    - Read storage: type (required), key (optional — omit to list all)\n" +
            "  set    - Write a value: type, key, value (all required)\n" +
            "  delete - Remove a key: type, key (both required)\n" +
            "  clear  - Clear all entries: type (required)",
            Schema(
                ("action", SStr("Action: get, set, delete, clear")),
                ("type", SStr("Storage type: 'local' or 'session' (default: local)")),
                ("key", SStr("Storage key (required for set/delete, optional for get)")),
                ("value", SStr("Value to store (required for set)"))
            ),
            required: ["action"]),

        Tool("browser_fetch",
            "HTTP from browser context (cookies/session). Prefer over execute-js fetch. json auto-sets Content-Type; " +
            "an explicit empty Content-Type sends no Content-Type header. " +
            "redirect:'manual' for 3xx; serverSide:true uses HttpClient and still attaches the WebView cookie jar unless includeBrowserCookies is false. " +
            "Every result includes identityUsed and cookiesSent (names only) — read those before treating a 200 as anonymous. " +
            "cookies:\"\" or Cookie:\"\" forces an anonymous server-side request. " +
            "Response includes durationMs (HTTP round-trip; excludes delayMs / gate wait).",
            Schema(
                ("url", SStr("Request URL (absolute or relative to current page)")),
                ("method", SStr("HTTP method: GET, POST, PUT, PATCH, DELETE (default: GET)")),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Request headers as key-value pairs" }),
                ("body", SStr("Request body as a string")),
                ("bodyBase64", SStr("UTF-8 body as standard Base64 — avoids shell/JSON quoting issues (ignored if body is set)")),
                ("bodyFile", SStr("Read request body from a local file path — avoids shell/JSON escaping entirely (ignored if body or bodyBase64 is set)")),
                ("json", new Dictionary<string, object> { ["description"] = "JSON request body — auto-serialized to string, auto-sets Content-Type: application/json" }),
                ("redirect", SStr("Redirect mode: 'follow' (default), 'manual' (capture 3xx without following), 'error' (throw on redirect)")),
                ("timeout", SInt("Request timeout in milliseconds (default: 30000)")),
                ("serverSide", SBool("Use server-side HttpClient instead of browser fetch(). Bypasses forbidden header restrictions " +
                    "(Referer, Origin, Host) while still sending the browser's cookies unless includeBrowserCookies is false. " +
                    "Not subject to CORS. Default: false.")),
                ("includeBrowserCookies", SBool("Server-side only. Merge the WebView cookie jar (default true). Set false for an anonymous probe. Response identityUsed/cookiesSent show what was sent.")),
                ("cookies", SStr("One-shot Cookie header. Does not change the browser jar. Empty string sends no cookies (anonymous, server-side)."))
            ),
            required: ["url"]),

        Tool("browser_fetch_raw",
            "Send HTTP/1.x bytes on a new TCP/TLS connection. headers is a raw block string so " +
            "Transfer-Encoding, Content-Length, and duplicate names go on the wire. " +
            "requestLine may include HTTP/1.0 or a nonstandard version token. Session header overrides are not applied.",
            Schema(
                ("url", SStr("Connect / SNI target (absolute http or https URL)")),
                ("requestLine", SStr("Request line, e.g. POST /search HTTP/1.0. Default: METHOD {path} HTTP/1.1")),
                ("method", SStr("Used only when requestLine is omitted (default GET)")),
                ("headers", SStr("Raw header block (not a JSON object) — one header per line")),
                ("body", SStr("Request body sent as UTF-8; Content-Length is not recomputed")),
                ("timeout", SInt("Timeout in milliseconds (default 15000)")),
                ("normalizeHeaders", SBool("Convert header newlines to CRLF (default true). Body is never rewritten."))
            ),
            required: ["url"]),

        Tool("browser_header_overrides",
            "Session header overrides for WebView2 browsing (replace if present, add if missing). " +
            "Does not apply to Send Direct, Raw, or server-side fetch. Actions: get, set, clear.",
            Schema(
                ("action", SStr("get (default), set, or clear")),
                ("headers", new Dictionary<string, object>
                {
                    ["type"] = "array",
                    ["description"] = "Replacement list for action=set: [{ name, value, enabled }]",
                    ["items"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["name"] = SStr("Header name"),
                            ["value"] = SStr("Header value"),
                            ["enabled"] = SBool("When false the row is kept but not applied")
                        },
                        ["required"] = new[] { "name" }
                    }
                })
            ),
            required: ["action"]),

        Tool("browser_fetch_batch",
            "Run multiple fetch() requests in the browser context (cookies, session, CORS). " +
            "Use concurrent=true to fire all at once for race-condition testing on authenticated APIs. " +
            "Each item supports the same fields as browser_fetch: url (required), method, headers, body, bodyBase64, bodyFile, json, timeout. " +
            "Set includeBodies=true (alias includeBody) to include response body previews (bodyMaxChars / maxBodyChars, default 200). " +
            "Without includeBodies, only bodyLen is returned — required for IDOR evidence. " +
            "durationMs is always included per result.",
            Schema(
                ("requests", new Dictionary<string, object>
                {
                    ["type"] = "array",
                    ["description"] = "Array of request objects (same fields as browser_fetch)",
                    // VS Code / Copilot reject bare items:{type:object}; require properties.
                    ["items"] = new Dictionary<string, object>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object>
                        {
                            ["url"] = SStr("Request URL (required)"),
                            ["method"] = SStr("HTTP method (default GET)"),
                            ["headers"] = new Dictionary<string, object>
                            {
                                ["type"] = "object",
                                ["description"] = "Request headers as key-value pairs",
                                ["additionalProperties"] = new Dictionary<string, object> { ["type"] = "string" }
                            },
                            ["body"] = SStr("Request body as a string"),
                            ["bodyBase64"] = SStr("UTF-8 body as standard Base64"),
                            ["bodyFile"] = SStr("Read body from a local file path"),
                            ["json"] = new Dictionary<string, object>
                            {
                                ["type"] = "object",
                                ["description"] = "JSON body (auto-serialized; sets Content-Type)"
                            },
                            ["redirect"] = SStr("Redirect mode: follow | manual | error"),
                            ["timeout"] = SInt("Timeout in ms (default 30000)")
                        },
                        ["required"] = new[] { "url" }
                    }
                }),
                ("concurrent", SBool("When true (default), all requests run in parallel; when false, sequential")),
                ("includeBodies", SBool("Include response body text in each result (truncated by bodyMaxChars)")),
                ("includeBody", SBool("Alias for includeBodies")),
                ("bodyMaxChars", SInt("Max response body chars per result when includeBodies is true (default 200, 0 = full body)")),
                ("maxBodyChars", SInt("Alias for bodyMaxChars")),
                ("includeTiming", SBool("Include durationMs per result (default true)"))
            ),
            required: ["requests"]),

        Tool("get_test_heuristics",
            "Returns curated test heuristics from the exploratory testing community — data attacks, web testing patterns, " +
            "accessibility checks, quality checklists, and prioritization strategies. " +
            "Call this when you need specific testing techniques or checklists to advise the user.",
            Schema()),

        Tool("browser_scripting_help",
            "Returns a curated C# scripting (.csx) cheat sheet for Trowser (REST: GET /api/scripting-help?topic=…). " +
            "Call this BEFORE writing a repeatable script, Quicktest, or browser_run_script code. " +
            "Scripts must use the C# automation API (Navigate/Click/Assert.*), never MCP tool-call JSON. " +
            "Optional topic selects a section: overview (default), map (MCP/REST→C#), interaction, assert, wait, " +
            "network, fetch, mock, security, laws, template, topics. " +
            "Full reference lives in trowserkit/scripting-reference.md.",
            Schema(
                ("topic", SStr("Section to return: overview (default), map, interaction, assert, wait, network, fetch, mock, security, laws, template, topics"))
            )),

        Tool("browser_inspiration",
            "Get a random testing inspiration message — a creative prompt, heuristic, or lateral-thinking trigger " +
            "to spark new test ideas. Use it to get inspired, but don't necessarily follow it unless it resonates. " +
            "Returns a single message string.",
            Schema()),

        Tool("browser_coverage",
            "Get the reflective coverage lens (REST equivalent: GET /api/coverage): pages visited, interactive " +
            "elements exercised, and which quality characteristics have been touched so far this session, derived " +
            "from the journal. Use it to spot gaps ('what haven't we looked at yet?') — it is awareness, not a target.",
            Schema()),

        Tool("browser_test_data",
            "Get a random test data string or security payload for form fields, JSON parameters, URLs, and similar inputs. " +
            "Use kind='strings' for general test strings (supports online mode when enabled in the Test Data dialog) " +
            "or kind='payloads' for security payloads (XSS, SQLi, SSRF, path traversal, etc.). " +
            "Defaults to the active kind selected in the Test Data dialog.",
            Schema(
                ("kind", SStr("Collection to use: 'strings' (default active kind) or 'payloads'"))
            )),

        Tool("browser_send_message",
            "Display a notification message to the human tester in the Trowser UI. " +
            "The message appears as an overlay at the bottom of the screen and auto-dismisses. " +
            "Use this to communicate important findings, status updates, or questions to the tester " +
            "while running automated or parallel tests.",
            Schema(
                ("text", SStr("The message text to display (required)")),
                ("level", SStr("Severity level: 'info' (blue, default), 'warning' (amber), or 'error' (red)")),
                ("duration", SInt("How long to show the message in milliseconds (default: 8000, min: 1000, max: 60000)"))
            ),
            required: ["text"]),

        Tool("browser_point",
            "Point at something for the human (agent→human handoff). A pointer is 'this, here, at this moment, and why': " +
            "it renders as an on-screen overlay for the tester and is journalled as the handoff record. " +
            "Target it with a ref (preferred), a CSS selector, semantic locator fields (role+name, testId, byText, label, placeholder), " +
            "or a rect {x,y,width,height} in CSS pixels. Use kind='absence' with a rect to point at where something SHOULD be but isn't " +
            "(a location, not an element). A frozen visual crop is captured automatically so the human still sees what you meant. " +
            "Symmetric with the human's '!?' snip — both land in the same store (see browser_pointers).",
            OptionalElementSchema(
                ("kind", SStr("Pointer kind: 'element' (default), 'region', 'range', 'absence' (something missing — use with rect), or 'artifact' (non-page UI)")),
                ("caption", SStr("Why you are pointing — what the human should notice (recommended)")),
                ("rect", SObj("Bounding rectangle in CSS pixels: {x, y, width, height, scrollX?, scrollY?}. Required for 'absence'/'region' with no element.")),
                ("checkpointId", SStr("Attach to a specific checkpoint (defaults to the most recent).")),
                ("source", SStr("For 'artifact' pointers: a label for where it came from (e.g. 'script console').")),
                ("url", SStr("Page URL (auto-captured if omitted).")),
                ("crop", SBool("Capture a frozen visual crop (default true)."))
            )),

        Tool("browser_pointers",
            "Read the pointers a human or agent has created (the shared handoff store). With no arguments, lists all pointers " +
            "with their kind, anchors, caption, author, status (resolved/stale/unresolvable) and frozen crop path. " +
            "Pass id to fetch one; add resolve=true to re-check whether that pointer's anchor still exists on the current page " +
            "(returns resolved=false and marks it 'unresolvable' rather than guessing — the crop remains the source of truth). " +
            "Filter with author ('human'|'agent'), kind, status, or checkpointId.",
            Schema(
                ("id", SStr("Fetch a single pointer by id (omit to list).")),
                ("resolve", SBool("With id: re-resolve the pointer against the live page and update its status.")),
                ("author", SStr("Filter: 'human' or 'agent'.")),
                ("kind", SStr("Filter by kind: element, region, range, absence, artifact.")),
                ("status", SStr("Filter by status: resolved, stale, unresolvable.")),
                ("checkpointId", SStr("Filter to pointers attached to a checkpoint."))
            )),

        Tool("browser_checkpoint",
            "Mark a sync point in the session. A checkpoint bounds 'what has happened since we last synced' — it records the " +
            "current journal position so a later handoff can send only what changed. Call with no arguments to create one " +
            "(optionally with a label). Pass action='list' to list checkpoints, or id to fetch one with a summary of activity since " +
            "(GUI actions, errors, pointers). Ids are session-scoped.",
            Schema(
                ("label", SStr("Optional human label for the checkpoint (e.g. 'before checkout').")),
                ("action", SStr("Set to 'list' to list checkpoints instead of creating one.")),
                ("id", SStr("Fetch a single checkpoint (with a 'since' summary) by id."))
            )),

        Tool("browser_decide",
            "Ask the human tester to make a call, as 2-6 lettered options they answer with one click in the AI Assistant panel. " +
            "Pick the lane by whether you can proceed without an answer: 'gate' blocks this tool call until they answer or the " +
            "timeout fires (use only when you genuinely cannot continue), 'steer' returns your default after an optional grace " +
            "period and keeps the question open so they can redirect you, 'review' never blocks and just puts the call on the record. " +
            "Always give a 'recommendation' — the tester should be confirming your judgement, not doing your thinking. " +
            "Set allowOther=true when none of your listed options fit — Other gets the next letter (e.g. A,B,C → D). " +
            "Attach 'pointerIds' from browser_point so they can see what the question is about. " +
            "Every answer, and every default that fires because nobody answered, is journalled.",
            Schema(
                ("question", SStr("What you need decided, in the tester's terms (required).")),
                ("options", SArr("2-6 answers, in order; keys A, B, C… are assigned automatically. With allowOther, at most 5 listed options. Objects with {label, detail} are also accepted.")),
                ("lane", SStr("'gate' (blocks until answered), 'steer' (default after grace, answer later), or 'review' (never blocks).")),
                ("recommendation", SStr("The option you recommend, by key ('B') or label. Strongly recommended.")),
                ("default", SStr("Option applied if nobody answers in time. Required in effect for 'steer' — defaults to your recommendation, else the first option.")),
                ("allowOther", SBool("When true, add a lettered Other option (next key after your list) so the tester can type a custom answer (REST alias option='other', note=<text>).")),
                ("graceMs", SInt("Steer lane only: hold the tool response up to this many ms, preferring a fast human answer before returning the provisional default (0 = immediate; max 120000).")),
                ("urgency", SStr("'low', 'normal' (default), or 'high'. High flashes the taskbar until the tester looks.")),
                ("timeout", SInt("How long the question stays open, in ms (default 300000 = 5 min; min 5000, max 1800000).")),
                ("pointerIds", SArr("Pointer ids from browser_point that show what the question is about.")),
                ("wait", SBool("Gate lane only: set false to create the question and poll browser_decisions later instead of blocking (default true)."))
            ),
            required: ["question", "options"]),

        Tool("browser_decisions",
            "Read the decisions you have asked the human for, and their answers. With no arguments, lists them all with status " +
            "(pending / answered / defaulted / expired / cancelled). Pass id to fetch one — this is " +
            "how you pick up a 'steer' answer after proceeding on the default, or a 'gate' answer you chose not to wait for. " +
            "Pass action='cancel' with id to withdraw a question you no longer need answered, so it stops asking for attention.",
            Schema(
                ("id", SStr("Fetch a single decision by id (omit to list).")),
                ("status", SStr("Filter: pending, answered, defaulted, expired, cancelled.")),
                ("lane", SStr("Filter: gate, steer, review.")),
                ("action", SStr("Set to 'cancel' (with id) to withdraw a pending question.")),
                ("reason", SStr("With action='cancel': why you no longer need it — recorded in the journal."))
            )),

        Tool("browser_journal_add",
            "Add a structured entry to the test journal (the session log / notes — there is no separate " +
            "browser_note, browser_log, or browser_journal write tool). Log observations, reasoning, bug reports, " +
            "enhancements, charters, test ideas, or user identity as you work. Creates a rich test narrative " +
            "interleaved with automatically captured actions and assertions. Use 'kind' to classify the entry. " +
            "For bug/enhancement, fill in the structured fields (steps/actual/expected/priority/oracle/notes) so " +
            "the finding can be extracted programmatically later. Rank bugs and enhancements with 'priority', not 'severity'. " +
            "Attach a 'screenshot' path (from browser_screenshot) " +
            "to any kind for a self-contained, visual bug report. Use 'tags' to categorize by functionality or quality " +
            "characteristic. The current page URL is auto-captured unless overridden with 'url'.",
            Schema(
                ("kind", SStr("Entry kind (default 'note'): 'note', 'user', 'charter', 'testing', 'test-idea', 'observation', 'bug', or 'enhancement'")),
                ("note", SStr("The primary text / title for the entry (required for most kinds; 'title' or 'text' are accepted aliases). A multi-line value uses the first line as title and the rest as markdown body.")),
                ("text", SStr("Alias for 'note' — the primary text / title")),
                ("title", SStr("Alias for 'note' — the primary text / title")),
                ("details", SStr("Optional markdown body (if omitted, extra lines of 'note' become the body)")),
                ("severity", SStr("Optional rank for note/observation/charter/etc.: 'info', 'low', 'medium', 'high', or 'critical'. Do not use for bug/enhancement — set 'priority' instead.")),
                ("evidence", SStr("Epistemic classification: 'observed' (directly seen), 'inferred' (interpretation), 'hypothesis' (worth exploring), or 'untested'. Defaults to inferred for LLM notes.")),
                ("screenshot", SStr("Optional screenshot file path (absolute or relative to the session log). Embedded inline by /api/journal/export.")),
                ("tags", SArr("Optional tags for grouping/filtering (e.g. ['login', 'security', 'accessibility']). Normalized to lowercase.")),
                ("url", SStr("Optional page URL. Auto-captured from the browser if omitted.")),
                ("steps", SStr("(bug/enhancement) Reproduction steps — a string or an array of strings")),
                ("actual", SStr("(bug/enhancement) Actual observed behaviour")),
                ("expected", SStr("(bug/enhancement) Expected behaviour")),
                ("priority", SStr("(bug/enhancement) Priority: 'low', 'medium', 'high', or 'critical'")),
                ("oracle", SStr("(bug/enhancement) Oracle: why you believe this is a bug / why the expected is correct")),
                ("notes", SStr("(bug/enhancement) Additional notes, workarounds, or context"))
            ),
            required: []),

        Tool("browser_journal_get",
            "Get test journal entries — the unified timeline of all session activity including actions, notes, " +
            "assertions, messages, bugs, enhancements, observations, charters, and test ideas from both the LLM and " +
            "human tester. Use 'since' for efficient polling: remember the last index you saw and request only new " +
            "entries. The response includes a revision counter and deleted indices so you can drop stale citations. " +
            "Filter by 'type' to extract only bugs, enhancements, or test ideas programmatically. " +
            "Filter by 'tag' for an exact tag match, or 'q' to search summary, details, URL, tags, and fields. " +
            "Use view=index for titles-only listing (default when journal exceeds 40 entries). " +
            "Use indexes=[3,7,12] to fetch full entries by id.",
            Schema(
                ("since", SInt("Return entries after this index (exclusive). Use for incremental polling.")),
                ("last", SInt("Return only the last N entries.")),
                ("type", SStr("Filter by entry type: 'action', 'assertion', 'message', 'error', 'screenshot', 'script-output', or a note kind ('note', 'bug', 'enhancement', 'observation', 'charter', 'testing', 'test-idea', 'user')")),
                ("source", SStr("Filter by source: 'api' (LLM/REST), 'gui' (human tester), 'system' (auto-generated)")),
                ("origin", SStr("Filter by origin: 'agent', 'user', or 'auto'")),
                ("evidence", SStr("Filter by evidence: observed, inferred, hypothesis, or untested")),
                ("tag", SStr("Filter by exact tag (case-insensitive)")),
                ("q", SStr("Free-text search across summary, details, URL, tags, and field values")),
                ("view", SStr("Response shape: 'index' (titles only) or 'full' (default for small journals)")),
                ("indexes", SArr("Fetch full entries for these journal indexes"))
            )),

        Tool("browser_journal_export",
            "Generate a formatted test report (HTML, Markdown, or JSON) from all journal entries. " +
            "Groups findings by kind — bugs and enhancements by priority, test ideas, observations — " +
            "and references attached screenshots by path (HTML export embeds screenshot files inline). " +
            "format=json is a true JournalEntry + pointer round-trip for Open/Save. " +
            "Optionally writes to a file path.",
            Schema(
                ("format", SStr("Output format: 'html', 'markdown' (default), or 'json'")),
                ("path", SStr("Optional file path to save the report to (absolute or relative to cwd)"))
            )),

        Tool("browser_journal_import",
            "Import a previously exported journal JSON bundle (entries plus attached pointers). " +
            "New indexes are assigned; pointer ids are remapped on collision. REST: POST /api/journal/import.",
            Schema(
                ("path", SStr("Path to a trowser-journal JSON file")),
                ("json", SStr("Inline journal JSON (alternative to path)")),
                ("content", SStr("Alias for json"))
            )),

        Tool("browser_journal_update",
            "Update an existing journal entry by index (from browser_journal_get). Partial: only supplied fields change. " +
            "Use this to refine a bug, observation, or note you or the tester already logged — do not add a duplicate.",
            Schema(
                ("index", SInt("Journal entry index to update (required)")),
                ("kind", SStr("Entry kind: 'note', 'user', 'charter', 'testing', 'test-idea', 'observation', 'bug', or 'enhancement'")),
                ("note", SStr("Primary text / title ('text' and 'title' are aliases)")),
                ("text", SStr("Alias for 'note'")),
                ("title", SStr("Alias for 'note'")),
                ("details", SStr("Optional markdown body (replaces the previous body when supplied)")),
                ("severity", SStr("For note/observation/etc.: 'info', 'low', 'medium', 'high', or 'critical' (empty to clear). Do not use for bug/enhancement — set 'priority' instead.")),
                ("evidence", SStr("Epistemic classification: observed, inferred, hypothesis, or untested")),
                ("screenshot", SStr("Screenshot file path (empty to clear)")),
                ("tags", SArr("Replace tags (lowercase). Empty array clears.")),
                ("url", SStr("Page URL")),
                ("steps", SStr("(bug/enhancement) Reproduction steps — string or array")),
                ("actual", SStr("(bug/enhancement) Actual observed behaviour")),
                ("expected", SStr("(bug/enhancement) Expected behaviour")),
                ("priority", SStr("(bug/enhancement) Priority: 'low', 'medium', 'high', or 'critical'")),
                ("oracle", SStr("(bug/enhancement) Why this is a bug / why expected is correct")),
                ("notes", SStr("(bug/enhancement) Additional notes"))
            ),
            required: ["index"]),

        Tool("browser_journal_delete",
            "Delete a journal entry by index. The index is never reused. Use when an entry is noise, a duplicate, or was logged in error.",
            Schema(
                ("index", SInt("Journal entry index to delete (required)"))
            ),
            required: ["index"]),

        Tool("browser_compact",
            "Compact the built-in assistant conversation context. Call after journaling a completed test segment. " +
            "Provide a summary of what was done and learned; optional openThreads, nextSteps (added to session tasks), " +
            "journalIndexes (full entries to inline), and keepLastTurns (default from settings). " +
            "The rewrite applies before the next model call — do not compact mid-test.",
            Schema(
                ("summary", SStr("What was done and learned in this segment (required)")),
                ("openThreads", SArr("Unresolved leads worth revisiting")),
                ("nextSteps", SArr("Tasks to carry forward (merged into session memory)")),
                ("journalIndexes", SArr("Journal entry indexes to inline in full after compact")),
                ("keepLastTurns", SInt("How many recent user/assistant turns to keep verbatim (default 10)"))
            ),
            required: ["summary"]),

        Tool("browser_session_memory",
            "Read or update volatile session memory (focus and tasks) used across compacts. " +
            "Actions: get (default), set_focus, add_task, update_task.",
            Schema(
                ("action", SStr("get | set_focus | add_task | update_task (default get)")),
                ("focus", SStr("(set_focus) Current testing focus")),
                ("text", SStr("(add_task) Task description")),
                ("id", SStr("(update_task) Task id")),
                ("status", SStr("(update_task) open | doing | done | dropped")),
                ("journalIndex", SInt("(add_task/update_task) Related journal entry index"))
            )),

        Tool("browser_ssl_list",
            "List all loaded client certificates for mutual TLS. Shows alias, subject, issuer, thumbprint, " +
            "expiry date, and which certificate is currently active. Certificates persist across sessions.",
            Schema()),

        Tool("browser_ssl_add",
            "Add a client certificate (.pfx or .p12) for mutual TLS authentication. " +
            "The certificate is stored securely (DPAPI-encrypted). Use the alias to refer to it later. " +
            "JKS files must be converted to PKCS#12 first (keytool -importkeystore).",
            Schema(
                ("filePath", SStr("Absolute path to .pfx or .p12 certificate file")),
                ("password", SStr("Password for the PKCS#12 file")),
                ("alias", SStr("User-friendly alias for this certificate (defaults to filename if omitted)"))
            ),
            required: ["filePath", "password"]),

        Tool("browser_ssl_remove",
            "Remove a client certificate by alias.",
            Schema(("alias", SStr("Alias of the certificate to remove"))),
            required: ["alias"]),

        Tool("browser_ssl_set_active",
            "Set which client certificate to use for mutual TLS, by alias. " +
            "Pass an empty alias or omit it to clear the active certificate (no client cert sent). " +
            "The active certificate is used for all WebView2 HTTPS requests that require client authentication.",
            Schema(("alias", SStr("Alias of the certificate to activate, or empty/null to clear")))),

        Tool("browser_ssl_get_active",
            "Get the currently active client certificate info, or null if no client certificate is set.",
            Schema()),

        // Peer management (cross-instance security testing)
        Tool("browser_peer_register",
            "Register a peer Trowser instance for cross-instance security testing (N-body authz). " +
            "Each peer is another Trowser process on localhost with its own session. " +
            "After registering, use browser_peer_fetch to send requests using the peer's cookies/session.",
            Schema(
                ("name", SStr("Unique name for this peer (e.g. 'admin', 'attacker', 'tenant-b')")),
                ("baseUrl", SStr("Base URL of the peer's API (e.g. 'http://localhost:6924'). Must be localhost.")),
                ("apiKey", SStr("API key for the peer instance (optional if peer has auth disabled)"))
            ),
            required: ["name", "baseUrl"]),

        Tool("browser_peers",
            "List all registered peer Trowser instances with health status and session names.",
            Schema()),

        Tool("browser_peer_fetch",
            "Send an HTTP request through a peer Trowser instance's browser session. " +
            "The request uses the peer's cookies, auth tokens, and session state — " +
            "perfect for BOLA/IDOR testing (compare responses across identities). " +
            "This is the workhorse for cross-instance security testing.",
            Schema(
                ("peer", SStr("Name of the registered peer")),
                ("url", SStr("Request URL (absolute or relative to peer's current page)")),
                ("method", SStr("HTTP method (default GET)")),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Request headers" }),
                ("json", new Dictionary<string, object> { ["description"] = "JSON body (auto-serialized)" }),
                ("body", SStr("Raw string body")),
                ("timeout", SInt("Request timeout in ms (default 30000)"))
            ),
            required: ["peer", "url"]),

        Tool("browser_peer_state",
            "Get the current page state (URL, title, elements) from a peer Trowser instance.",
            Schema(("peer", SStr("Name of the registered peer"))),
            required: ["peer"]),

        Tool("browser_peer_navigate",
            "Navigate a peer Trowser instance to a URL.",
            Schema(
                ("peer", SStr("Name of the registered peer")),
                ("url", SStr("URL to navigate to"))
            ),
            required: ["peer", "url"]),

        Tool("browser_peer_screenshot",
            "Take a screenshot of a peer Trowser instance's current page.",
            Schema(
                ("peer", SStr("Name of the registered peer")),
                ("format", SStr("Image format: 'jpeg' (default) or 'png'")),
                ("quality", SInt("JPEG quality 1-100 (default 60)"))
            ),
            required: ["peer"]),

        Tool("browser_peer_unregister",
            "Remove a peer Trowser instance from the registry.",
            Schema(("name", SStr("Name of the peer to unregister"))),
            required: ["name"]),

        // AuthZ tools
        Tool("browser_authz_probe",
            "Batch authorization boundary scanner. Tests whether the current session has access to a list of endpoints. Returns structured results with auto-classification (allowed/denied/error). Useful for mapping access control boundaries.",
            Schema(
                ("endpoints", SObjArr("Array of endpoints to probe: strings (URLs for GET) or objects with url, method?, headers?, json?, body?")),
                ("classify", SBool("Auto-classify responses: 2xx=allowed, 4xx=denied, 5xx=error (default: true)")),
                ("ensureOrigin", SBool("Navigate browser to the target origin before probing, so cookies are sent (default: false)"))
            ),
            required: ["endpoints"]),

        Tool("browser_authz_diff",
            "Cross-identity authorization comparison. Runs the same endpoints on both the local session AND one or more peer sessions, producing a structured diff with auto-classification: BOLA_SUSPECTED, FILTERED_RESPONSE, PROPERLY_DENIED, REDIRECT_DENIED, ERROR_BEFORE_AUTH, DENIED_BOTH.",
            Schema(
                ("peer", SStr("Single registered peer name (legacy; use peers for multiple)")),
                ("peers", SArr("Array of registered peer names to compare against")),
                ("endpoints", SObjArr("Array of endpoints: strings (URLs for GET) or objects with url, method?, headers?, peerHeaders?, json?, body?")),
                ("includeBody", SBool("Include full response bodies in results (default: false)")),
                ("includeBodyOnMismatch", SBool("Include bodies only when local and peer responses differ (default: false)")),
                ("ensureOrigin", SBool("Auto-navigate peer to the target origin before fetching (default: true)")),
                ("leakTokens", SArr("Strings to search for in peer responses (e.g. patient names, IDs) to detect data leaks")),
                ("bodyMatch", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Response comparison options: { strategy?: exact|normalizedJson|structural, ignoreFields?: string[] }. normalizedJson strips volatile fields (timestamp, requestId, etc.) before hashing."
                }),
                ("ignoreFields", SArr("Shorthand: when set without bodyMatch, enables normalizedJson with these field names")),
                ("structuralMatch", SBool("Shorthand: compare JSON structure only (strategy=structural)"))
            ),
            required: ["endpoints"]),

        Tool("browser_session_identity",
            "Live session identity introspection: session name, cookies (redacted previews), jwtCookies (alg/exp/iss), storage tokens, inferred auth mechanism. A JWT in localStorage or sessionStorage is reported as storage-token even when a session cookie is also present. REST: GET /api/session/identity.",
            Schema(),
            required: []),

        Tool("browser_identities",
            "List captured identity snapshots (metadata only). REST: GET /api/identities.",
            Schema(),
            required: []),

        Tool("browser_identity_capture",
            "Capture portable identity snapshot (cookies, storage, optional auth headers). REST: POST /api/identity/capture. Blocked in safe mode.",
            Schema(
                ("name", SStr("Identity name (required)")),
                ("includeAuthHeaders", SBool("Include Authorization headers from network log (default true)")),
                ("authHeaderMaxAgeMinutes", SInt("Max age of auth headers in minutes (default 30)"))
            ),
            required: ["name"]),

        Tool("browser_identity_apply",
            "Apply captured identity to self or peer. Optional navigateTo and verify probe. REST: POST /api/identity/apply. Blocked in safe mode.",
            Schema(
                ("name", SStr("Captured identity name (required)")),
                ("target", SStr("self (default) or peer")),
                ("peer", SStr("Registered peer when target=peer")),
                ("navigateTo", SStr("URL to open after apply")),
                ("verify", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Optional { url, expectStatus?, method?, headers?, body?, timeoutMs? } liveness probe"
                })
            ),
            required: ["name"]),

        Tool("browser_identity_handoff",
            "SSO/MFA handoff: action=start waits for human login; action=status polls; action=cancel aborts. Auto-captures on delta. REST: POST/GET /api/identity/handoff.",
            Schema(
                ("action", SStr("start (default), status, or cancel")),
                ("name", SStr("Identity name (required)")),
                ("timeoutMs", SInt("Timeout ms (default 300000)")),
                ("livenessUrl", SStr("Optional URL expected to return 2xx after login")),
                ("autoCapture", SBool("Auto-capture on status when change detected (default true)"))
            ),
            required: ["name"]),

        Tool("browser_authz_fuzz",
            "Parameter fuzzing with crash detection. Takes a URL template with {param} placeholders and an array of parameter sets. Substitutes each set into the template, fires the request, and classifies responses. Detects server crashes (NullPointerException, stack traces, etc.). Set autoPayloads: true to auto-generate boundary values (empty, null, -1, huge), type confusion ([], {}, NaN), XSS/SQLi/traversal payloads, unicode edge cases, and format strings from your baseline parameters.",
            Schema(
                ("endpoint", SStr("URL template with {param} placeholders, e.g. 'https://app.com/api/case/{hsaId}/items'")),
                ("method", SStr("HTTP method (default GET)")),
                ("parameterSets", SObjArr("Array of parameter objects: { paramName: value, body?: '...', headers?: {...} }. 'body' is the request body, others are URL substitutions.")),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Default headers for all requests" }),
                ("bodyTemplate", SStr("Request body template with {param} placeholders for substitution, e.g. '{\"hsaId\":[\"{facilityId}\"]}''. Parameters from each parameterSet are substituted. Auto-sets Content-Type to application/json if body starts with { or [.")),
                ("autoPayloads", SBool("Auto-generate smart mutation payloads from your baseline parameter sets: boundary values (empty, null, 0, -1, 99999999), type confusion ([], {}, NaN, Infinity), long strings (1K/10K), XSS/SQLi/SSTI/traversal probes, unicode edge cases, format strings (default: false)")),
                ("classify", SBool("Auto-classify responses (default: true)")),
                ("detectCrashPattern", SBool("Detect crash patterns in 5xx responses (NullPointerException, stack traces, etc.) (default: true)"))
            ),
            required: ["endpoint", "parameterSets"]),

        Tool("browser_authz_boundary",
            "Authorization boundary testing. Tests a URL with authorized vs unauthorized parameter values and detects when unauthorized access is granted. Compares unauthorized responses against the authorized baseline to detect BOLA/IDOR. Accepts legacy single-endpoint fields or endpoints[] for batch tests.",
            Schema(
                ("endpoint", SStr("Legacy: URL template with {parameter} placeholder (alias: url)")),
                ("url", SStr("URL template with {parameter} placeholder")),
                ("endpoints", SObjArr("Batch mode: array of { url, parameter, authorizedValues, unauthorizedValues, method?, headers?, json?, body?, bodyTemplate?, peer? }")),
                ("parameter", SStr("Name of the parameter to vary (matches {parameter} in the URL or bodyTemplate)")),
                ("authorizedValues", SArr("Values the current session SHOULD have access to (establishes baseline)")),
                ("unauthorizedValues", SArr("Values the current session should NOT have access to")),
                ("method", SStr("HTTP method (default GET)")),
                ("peer", SStr("Optional: run unauthorized tests through a peer's session instead of the local one")),
                ("headers", new Dictionary<string, object> { ["type"] = "object", ["description"] = "Request headers" }),
                ("json", new Dictionary<string, object> { ["type"] = "object", ["description"] = "JSON request body" }),
                ("body", SStr("Raw request body")),
                ("bodyTemplate", SStr("Request body template with {parameter} placeholder for substitution, e.g. '{\"BasketId\": {basketId}}'. Auto-sets Content-Type to application/json if body starts with { or [.")),
                ("bodyMatch", new Dictionary<string, object>
                {
                    ["type"] = "object",
                    ["description"] = "Baseline comparison options: { strategy?: exact|normalizedJson|structural, ignoreFields?: string[] }"
                }),
                ("ignoreFields", SArr("Shorthand: when set without bodyMatch, enables normalizedJson with these field names")),
                ("structuralMatch", SBool("Shorthand: compare JSON structure only (strategy=structural)"))
            ),
            required: []),

        Tool("browser_authz_model",
            "Get or set the persisted access model for a host: per-(method,urlTemplate) declared sensitivity/ownership " +
            "(public/internal/sensitive x shared/perUser/perTenant/roleGated) and identity role/tier/ownerTags. " +
            "Declared intent the Live Authz Shadow compares cross-identity replays against. " +
            "mode=get (default) reads/optionally heuristic-seeds from the attack surface map; mode=set upserts resources/identities " +
            "(source defaults to human when omitted). REST: GET/PUT /api/authz/model.",
            Schema(
                ("mode", SStr("get (default) or set")),
                ("host", SStr("Target host. example.com, example.com:443, and example.com:80 are one key. A non-default port (127.0.0.1:8099) stays. get defaults to the current tab.")),
                ("seed", SBool("get only: heuristic-seed unclassified resources from the attack surface map before returning (default false)")),
                ("resources", SObjArr("set only: array of { method, urlTemplate, sensitivity?, ownership?, source?, confidence?, notes? }")),
                ("identities", SObjArr("set only: array of { name, role?, tier?, ownerTags? }"))
            ),
            required: []),

        Tool("browser_authz_shadow",
            "Control the Live Authz Shadow: watches normal browsing and replays authz-relevant requests through registered peers. " +
            "Wire verdicts are PascalCase, including mode export: ConfirmedLeak, BolaSuspected, SameShapeDifferentData, NeedsReview, FilteredResponse (different content — not proof of scoping), " +
            "ProperlyDenied, Inconclusive, ReplayedWrite (both identities got their own write success; peerMutated), PeerUnauthenticated (a write with peerAuthApplied none). The verdict filter is case-insensitive. " +
            "Resource type Other is replayed unless the response is a script, stylesheet, font, or decorative image. " +
            "When the owner call sent Authorization, replay installs the peer's header from the peer's own requests, a JWT cookie such as token, or storage. " +
            "peerAuthApplied is cookie, bearer, both, or none. A read denial with none is Inconclusive. A 200 with the same body, when the owner sent a cookie or Authorization, is ConfirmedLeak (missing authentication), not a public page. HTML shells stay public. " +
            "A generic id is not an owner token. A token already in the replayed URL does not count. " +
            "Status includes skippedBySafetyMode, skippedResourceType, skippedNonSuccess, skippedThirdParty, replayFailures, and peerMutatedCount. " +
            "mode clear drops results and withdraws pending review cards. Skip reasons stay on the access model. " +
            "Off by default. GET/HEAD/OPTIONS/QUERY replay at every mode, including passive. POST/PUT/PATCH/DELETE need active or aggressive. " +
            "execute-js fetch() is not replayed. Peer baseUrl must be http://localhost:<port>, not 127.0.0.1. " +
            "mode export returns a bundle (results + access models); mode import restores it from path or bundle. replaceResults defaults to false and will not overwrite human/AI classifications with heuristics. " +
            "GUI-only. REST: POST /api/authz/shadow.",
            Schema(
                ("mode", SStr("enable | disable | status (default) | results | clear | export | import")),
                ("safetyMode", SStr("enable only: passive | safe | active | aggressive (default safe)")),
                ("peers", SArr("enable only: peer names to replay against (default: all currently registered peers)")),
                ("sinceId", SInt("results only: only return results with Id greater than this")),
                ("verdict", SStr("results only: filter to one verdict kind")),
                ("path", SStr("export: write the bundle to this file. import: read the bundle from this file.")),
                ("bundle", SObj("import: the object returned by export, when path is omitted")),
                ("replaceResults", SBool("import: drop the in-memory result log before restoring (default false)"))
            ),
            required: []),

        Tool("browser_authz_coverage",
            "Build a BAC (Broken Access Control) coverage report for a host: cross-references the access model " +
            "(browser_authz_model — declared intent), the attack surface map (what endpoints exist), and any " +
            "Live Authz Shadow results (browser_authz_shadow — what's actually been cross-identity tested) into " +
            "one coverage numerator/denominator, findings grouped by verdict with provenance, remaining gaps, " +
            "and suggested next actions. Returns JSON plus a Markdown report. REST: POST /api/authz/coverage.",
            Schema(
                ("host", SStr("Target host. example.com:443 is the same key as example.com. A non-default port stays. Defaults to the current tab. testedPercent is coverage, not a security score.")),
                ("markdown", SBool("Include a rendered Markdown report in the response (default true)"))
            ),
            required: []),
    ];

    #endregion
}
