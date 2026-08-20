# Trowser C# Scripting Reference

Complete reference for writing Trowser test scripts (`.csx` files). Scripts are C# with full `async/await` support, executed by the Roslyn scripting engine with the automation API available as top-level globals.

**AI Assistant / MCP:** call `browser_scripting_help` for a curated cheat sheet (optional `topic`: overview, map, interaction, assert, …). Do not treat MCP tool-call JSON as a runnable script.

## CLI Usage

### Executable Location

```
C:\work\programming\Trowser\src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe
```

Fallback (Debug build):
```
C:\work\programming\Trowser\src\Trowser\bin\Debug\net8.0-windows\win-x64\Trowser.exe
```

### Syntax

```bash
Trowser.exe --run <script.csx> [--url <url>] [--output <file>] [--visible] [--timeout <seconds>]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--run <script.csx>` | **Required.** Path to C# script file. | -- |
| `--url <url>` | Pre-navigate to this URL before running the script. | none |
| `--output <file>` | Write all output to this file (stdout is always used too). | none |
| `--visible` | Show the browser window (hidden by default in CLI mode). | hidden |
| `--timeout <seconds>` | Maximum script execution time. | 120 |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success -- all assertions passed (or no assertions were made) |
| `1` | Test failure -- one or more assertions failed |
| `2` | Script error (compilation error, runtime error, file not found, or timeout) |

---

## Stopping Scripts

Scripts can be stopped mid-execution:

- **Script Console:** Click the **■ Stop** button (the Run button changes to Stop while a script is running), or press <kbd>Ctrl</kbd>+<kbd>Enter</kbd> again.
- **CLI mode:** The `--timeout` flag sets a maximum execution time. When the timeout expires, the script is cancelled automatically.

Cancellation is **cooperative**: the script stops at the next async checkpoint — `Sleep`, `Navigate`, `Click`, `Type`, `Fetch`, `WaitForElement`, `WaitForRequest`, `WaitForIdle`, or any other method that calls the browser. Pure CPU loops without `await` calls cannot be interrupted.

When a script is cancelled, the output shows `[Cancelled] Script stopped by user` with the elapsed time.

---

## Quicktests

The **Quicktests ▾** dropdown in the Script Console toolbar provides ready-made test scripts. Select one to load it into the editor, then click Run.

| Name | Description |
|------|-------------|
| `1 AttackSurfaceFromNetwork` | Attack surface map from captured network traffic (browse the app first) |
| `3 AutoScan` | Attack-surface discovery + targeted scanners (SQLi, IDOR, CSRF, path-traversal, mass-assignment). Browse first. |
| `BackAndForward` | Navigate Back 10 times, Forward 10 times, verify the page is unchanged |
| `BiggestFiles` | List the 10 largest files from captured network traffic |
| `BrowserCompatibilityScan` | Check if JavaScript contain very modern things |
| `ChecksAfterSession` | A combination of some of the quicktests |
| `ConsoleAndNetworkErrors` |  Looks at history of errors in console and network |
| `FaultInjection` | Fault injection: auto-discovers APIs, injects faults (500, 404, empty, invalid JSON, slow, mutation), checks for crashes |
| `3 FirewallTest` | Active CSP / SRI / iframe sandbox / Permissions-Policy bypass attempts in the live page |
| `FullSiteHealth` | Comprehensive health check: all audits on the current page |
| `GUIAudit` | GUI visual consistency + image optimization |
| `HtmlValidation` | Inspects HTML with 3rd party html-validate |
| `5 HttpSmuggling` | Raw TCP HTTP smuggling: timing + differential-response confirmation (CL-TE, TE-CL, TE-TE, CL-CL) against the document URL |
| `6 WafBypass` | WAF bypass technique probe: block detection + encoding/header/path/HPP transforms (browse first for query-param discovery) |
| `4 CstiScan` | Client-side template injection (CSTI): DOM-aware {{7*7}} probes via URL query/hash (browse first; best on AngularJS/Vue/Handlebars) |
| `2 JavaScriptVulnerabilities` | Retire.js CVE scan for JavaScript libraries on the current page |
| `2 JwtAnalysis` | JWT hygiene: decode tokens from cookies/storage; flag alg, exp, sensitive claims |
| `2 JsAudit` | Fetch external `script[src]` bundles; heuristic scan for secrets / internal URLs / debug markers |
| `LinkCheck` | Check all links on the page for broken URLs |
| `MonkeyTest` | Random actions with gremlins.js and Smart Monkey |
| `2 OidcFromNetwork` | OIDC provider audit; auto-detect issuer from network log (browse / login first) |
| `PerformanceCheck` | Web Vitals performance check on the current page |
| `ResponsiveAccessibility` | WCAG AA check across all viewport presets |
| `TabOrderCheck` | Real Tab + Shift+Tab walk; skipped focusables, traps, reading order, Shift+Tab consistency |
| `ToggleScreenCurtain` | Toggle blind-testing screen curtain (same as Ctrl+B) |
| `RequestFuzzer` | Browser-context fuzzing from the network log (JSON POST/PUT/PATCH and GET query params) |
| `2 SecretsHarvest` | Unified secret/credential scan: JS bundles, cookies, storage, network responses, page text, source maps |
| `2 SecurityScan` | Broad passive security: tech stack, JS CVEs, headers, CORS, XSS, mixed content, cookies, source maps, web storage, HTTP methods, path discovery |
| `4 SamlFromNetwork` | Decode latest SAML from the network log and flag security issues (SSO flow first) |
| `SmallAccessibility` | Quick WCAG AA accessibility check on the current page |
| `3 GraphqlAnalysis` | GraphQL security probes; auto-detect endpoint from network log |
| `ThirdPartyAudit` | Third-party resource inventory (domains, sizes, SRI coverage) |
| `2 ThirdPartySecurity` | Third-party inventory + SRI (Security quicktests folder) |
| `TotalRefresh` | Refresh the page 100 times and check for errors |
| `TrowserSmokePass` | A simple smoke pass of Trowser itself |
| `SurpriseMe` | Runs a random non-destructive quicktest from the catalog (category-balanced; excludes destructive/slow tests). Pair with **Watch mode** for a new check on each navigation. |

### `SurpriseMe()` helper

Scripts can call `await SurpriseMe()` directly. It picks a random eligible embedded quicktest, logs `Surprise! Running: <name>`, executes it with the same globals (Log, Assert, scanners), and returns the chosen name. The last pick is also available as `LastSurpriseQuicktest` on the automation context.

**REST:** `POST /api/surpriseme` — no body required; returns `{ quicktest, success, assertions, elapsedMs }`.

**MCP:** `browser_surpriseme` — same behavior.

Blocked in `--safe` mode (same as `execute-script` / `browser_run_script`).

### Write your own quicktest (UserScripts)

You are not limited to the built-in catalog. Drop your own `.csx` files into the user quicktests folder and they appear under **Quicktests ▾ → UserScripts**:

```
Documents\Trowser Quicktests
```

- The first time Trowser opens this folder it seeds a `README.md` (a short authoring guide) and an `ExampleQuicktest.csx` you can copy.
- Subfolders become nested submenus, so you can organise scripts however you like.
- The **UserScripts** submenu rescans the folder every time you open it — new files show up immediately, no restart needed. Use **UserScripts → Open folder…** to jump straight there.
- Selecting an item loads the script into the Script Console; press **Run** (or `Ctrl+Enter`) to execute it. A user quicktest is just a normal Trowser C# script and has the full scripting API described in this document.
- User quicktests are **not** included in the randomized `SurpriseMe` pool (that stays limited to the vetted embedded catalog), but they run with full script access — keep any state-mutating actions behind an explicit safety check.

---

## Recording Scripts

Trowser can **record user interactions** and generate a `.csx` script automatically. This is useful for creating regression tests, reproducing bugs, and providing LLMs with concrete interaction sequences.

### How to Record

1. Click the **● Record** button in the toolbar (turns red while recording).
2. Interact with the page normally — click buttons, type in forms, select dropdowns, navigate.
3. Click **● Record** again to stop. The generated script appears in the Script Console.

### What Gets Recorded

| Action | Generated Script |
|--------|-----------------|
| Click a button | `await Click(ByRole("button", "Submit"));` |
| Click a link | `await Click(ByRole("link", "Home"));` |
| Click a tab | `await Click(ByRole("tab", "Settings"));` |
| Type in a field | `await Type(ByLabel("Email"), "user@example.com");` |
| Select a dropdown option | `await Select(ByLabel("Country"), "us");` |
| Open a dropdown menu (hover) | `await Hover(ByRole("link", "Components"));` |
| Press keyboard keys | `await PressKey("Escape");` |
| Navigate to a new page | `await Navigate("https://example.com");` |

The recorder uses **semantic locators** (`ByRole`, `ByLabel`, `ByText`, etc.) whenever possible, falling back to CSS selectors only when needed. Dynamic IDs are automatically avoided.

### Right-Click Context Menu (During Recording)

While recording, right-clicking on any element shows two extra menu items:

| Menu Item | Generated Script | Purpose |
|-----------|-----------------|---------|
| **Assert text** | `await AssertPageContains("visible text");` | Assert that the element's text is visible on the page |
| **Element of interest** | `// Element of interest: tab "Settings"` | Add a comment marking this element as noteworthy for LLM-driven testing |

**Assert text** is useful for adding verification steps while recording — e.g., right-click a heading after a page load to assert it appeared.

**Element of interest** adds a comment that helps LLMs understand which elements are important to interact with or verify when expanding the test script.

### Playing Scripts

Click the **▶ Play** button to open a file picker, select a `.csx` file, and execute it immediately — no need to copy the script into the Script Console first.

### Script to REST API Translation

Recorded scripts can serve as a guide for LLM agents using the REST API. The table below shows how script lines map to REST calls:

| Script | REST API Call |
|--------|--------------|
| `await Click(ByRole("button", "Submit"))` | `POST /api/click {"role":"button","name":"Submit"}` |
| `await Click(ByText("Sign in"))` | `POST /api/click {"byText":"Sign in"}` |
| `await Click(ByRole("tab", "Settings"))` | `POST /api/click {"role":"tab","name":"Settings"}` |
| `await Type(ByLabel("Email"), "user@example.com")` | `POST /api/type {"label":"Email","text":"user@example.com"}` |
| `await Type(ByPlaceholder("Search..."), "query")` | `POST /api/type {"placeholder":"Search...","text":"query"}` |
| `await Select(ByLabel("Country"), "us")` | `POST /api/select {"label":"Country","value":"us"}` |
| `await Hover(ByRole("link", "Components"))` | `POST /api/hover {"role":"link","name":"Components"}` |
| `await PressKey("Tab")` | `POST /api/key {"key":"Tab"}` |
| `await Navigate("https://example.com")` | `POST /api/navigate {"url":"https://example.com"}` |
| `await GoBack()` | `POST /api/go-back` |
| `await GoForward()` | `POST /api/go-forward` |
| `await AssertPageContains("Welcome")` | `POST /api/assert/page-contains {"text":"Welcome"}` |
| `await WaitForIdle()` | `POST /api/wait-for-idle {"quietPeriod":500,"timeout":10000}` |
| `await WaitForRequest("/api/data", "POST", 200)` | `POST /api/wait-for-network {"urlPattern":"/api/data","method":"POST","status":200}` |
| `await SetNetworkThrottle("3G")` | `POST /api/network/throttle {"preset":"3G"}` |
| `await ClearNetworkThrottle()` | `DELETE /api/network/throttle` |
| `await GetAllStorage("local")` | `GET /api/storage?type=local` |
| `await SetStorageItem("local", "key", "val")` | `POST /api/storage/set {"type":"local","key":"key","value":"val"}` |
| `await Fetch("/api/users", "POST", body: "{...}")` | `POST /api/fetch {"url":"/api/users","method":"POST","body":"{...}"}` |
| `await FetchBatchAsync(items, concurrent: true)` | `POST /api/fetch/batch {"requests":[...],"concurrent":true}` |

**Locator mapping:**

| Script Locator | REST Property |
|----------------|---------------|
| `ByRole("button", "Submit")` | `{"role": "button", "name": "Submit"}` |
| `ByLabel("Email")` | `{"label": "Email"}` |
| `ByText("Sign in")` | `{"byText": "Sign in"}` |
| `ByPlaceholder("Search...")` | `{"placeholder": "Search..."}` |
| `ByTestId("submit-btn")` | `{"testId": "submit-btn"}` |

---

## Script Environment

### Available Imports (automatic)

- `System`, `System.Collections.Generic`, `System.Linq`, `System.Text`
- `System.Text.Json`, `System.Text.RegularExpressions`, `System.Threading.Tasks`
- `Trowser.Automation`, `Trowser.Accessibility`, `Trowser.Compatibility`, `Trowser.Consistency`, `Trowser.HtmlValidation`, `Trowser.LinkChecking`, `Trowser.MixedContent`, `Trowser.Performance`, `Trowser.Robustness`, `Trowser.Security`, `Trowser.Testing`, `Trowser.TextExtraction`, `Trowser.ThirdParty`, `Trowser.XssAudit`

### Global Objects

| Global | Type | Description |
|--------|------|-------------|
| `Assert` | `TestAssert` | Assertion library |
| `Console` | `ConsoleLog` | Console message log with query methods |
| `Network` | `NetworkLog` | Network traffic log with query methods |

All automation methods are available as top-level calls (no object prefix needed):
`Navigate`, `GoBack`, `GoForward`, `Click`, `Type`, `Select`, `Hover`, `PressKey`, `Scroll`, `GetText`, `GetAttribute`, `GetProperty`, `IsChecked`, `Exists`, `Count`, `Extract`, `GetWebMcpTools`, `CallWebMcpTool`, `WaitForElement`, `WaitForRequest`, `WaitForNavigation`, `WaitForFinalNavigation`, `WaitForIdle`, `Sleep`, `ExecuteJs`, `GetRandomTestData`, `Fetch`, `FetchBatchAsync`, `Screenshot`, `Log`, `GetCookies`, `GetCookie`, `SetCookie`, `DeleteCookie`, `ClearCookies`, `GetAllStorage`, `GetStorageItem`, `SetStorageItem`, `DeleteStorageItem`, `ClearStorage`, `SetNetworkThrottle`, `ClearNetworkThrottle`, `MockResponse`, `RemoveMock`, `ClearMocks`, `GetMockRules`, `AddInterceptRule`, `RemoveInterceptRule`, `ClearInterceptRules`, `GetInterceptRules`, `GetPendingRequests`, `ResolvePendingRequest`, `RunInterrupterTest`, `ClearAll`, `ClearSession`, `PrintStorageSecurityReport`, `AssertStorageSecurity`, `CheckHttpMethods`, `PrintHttpMethodsReport`, `AssertHttpMethodsClean`, `CheckAttackSurface`, `PrintAttackSurfaceReport`, `TryDecodeSamlFromNetwork`, `PrintSamlFromNetworkReport`, `AssertSamlSecurity`, `RunAutoScan`, `PrintAutoScanReport`, `AssertAutoScanClean`, `RunSecretsHarvest`, `PrintSecretsHarvestReport`, `AssertSecretsClean`, `RunFirewallTest`, `PrintFirewallTestReport`, `AssertFirewallTestClean`, `RunJwtAnalysis`, `PrintJwtAnalysisReport`, `AssertJwtAnalysisClean`, `RunOidcAnalysis`, `PrintOidcAnalysisReport`, `AssertOidcAnalysisClean`, `RunGraphqlAnalysis`, `PrintGraphqlAnalysisReport`, `AssertGraphqlAnalysisClean`, `RunJavaScriptStaticAudit`, `PrintJavaScriptStaticAuditReport`, `AssertJavaScriptStaticAuditClean`, `RunHttpSmugglingScan`, `PrintHttpSmugglingReport`, `AssertHttpSmugglingClean`, `RunWafBypassScan`, `PrintWafBypassReport`, `AssertWafBypassEffective`.

Locator factory methods (also top-level): `ByRole`, `ByLabel`, `ByText`, `ByPlaceholder`, `ByTestId`, `ByFrame`.

Frame / download / drag / emulation / forensics (also top-level): `GetFrames`, `ByFrame`, `Drag`, `WaitForDownload`, `GetDownloads`, `AssertDownload`, `ClearDownloads`, `SetEmulation`, `ClearEmulation`, `ExportHar`, `StartTrace`, `StopTrace`, `GetTrace`, `ExportTrace`, `ClearTrace`.

---

## Navigation

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `Navigate(url)` | `string url` | `Task` | Navigate to URL and wait for page load. |
| `GoBack()` | -- | `Task` | Navigate back in history. Waits for page load. Throws if no history. |
| `GoForward()` | -- | `Task` | Navigate forward in history. Waits for page load. Throws if no history. |
| `GetCurrentUrl()` | -- | `Task<string>` | Current page URL |
| `GetTitle()` | -- | `Task<string>` | Current page title |
| `GetPageSource()` | -- | `Task<string>` | Full HTML source of the page |
| `GetPageText()` | -- | `Task<string>` | All visible text on the page (`document.body.innerText`) |
| `GetAllPageText()` | -- | `Task<string>` | All text nodes including hidden/off-screen; shadow DOM; one trimmed segment per line (newline-separated); excludes script/style/noscript/template |
| `GetScreenReaderTexts()` | -- | `Task<string>` | Screen reader strings: `alt`, `aria-label`, `aria-labelledby`/`aria-describedby`, `title`, SVG `title`/`desc`; shadow DOM; one line each with `[kind]` prefix |

```csharp
await Navigate("https://example.com");
var url = await GetCurrentUrl();
var title = await GetTitle();

// Back/forward navigation (requires history)
await GoBack();
await GoForward();
```

---

## Element Interaction

All interaction methods **traverse shadow DOM** and support **auto-waiting** -- they automatically wait for elements to be ready before acting. You can use CSS selectors, shadow-piercing `>>>` selectors, or **semantic locators**.

### Auto-Waiting

- **Click, Type, Select, PressKey:** Wait for the element to be **visible** and **enabled**.
- **Hover:** Wait for the element to be **visible**.
- **GetText, GetAttribute:** Wait for the element to **exist** in the DOM.

Default timeout: **5000ms** (configurable via `DefaultActionTimeout`). Override per-call with the optional `timeoutMs` parameter. Set to `0` to disable (immediate, legacy behavior).

### Interaction Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `Click(selector, timeoutMs?)` | `string selector, int? timeoutMs = null` | `Task` | Click an element. Auto-waits for visible + enabled. If the element is a navigation link (`<a href>`), automatically waits for the page navigation to complete. |
| `Type(selector, text, timeoutMs?, html?)` | `string selector, string text, int? timeoutMs = null, string? html = null` | `Task` | **Clear** the field, then type text. Auto-waits for visible + enabled. Automatically detects **contenteditable** elements (rich text editors) and uses `execCommand('insertText')`. Pass `html` to insert formatted HTML via `insertHTML`. |
| `Select(selector, value, timeoutMs?)` | `string selector, string value, int? timeoutMs = null` | `Task` | Select dropdown option by value. Auto-waits for visible + enabled. |
| `Hover(selector, timeoutMs?)` | `string selector, int? timeoutMs = null` | `Task` | Hover over element using CDP mouse movement — triggers CSS `:hover` states and JS mouse events. Auto-waits for visible. |
| `PressKey(key, selector?, modifiers?, timeoutMs?)` | `string key, string? selector, string[]? modifiers, int? timeoutMs` | `Task` | Send keyboard key press. When selector is given, auto-waits for visible + enabled. |
| `GetText(selector, timeoutMs?)` | `string selector, int? timeoutMs = null` | `Task<string>` | Get inner text (pierces shadow DOM). Auto-waits for element to exist. |
| `GetAttribute(selector, attribute, timeoutMs?)` | `string selector, string attribute, int? timeoutMs = null` | `Task<string>` | Get attribute value (pierces shadow DOM). Auto-waits for element to exist. Prefer unquoted CSS attribute values (`meta[http-equiv=Content-Security-Policy]`) or `GetMetaContent` for meta tags. |
| `GetMetaContent(name, httpEquiv?, timeoutMs?)` | `string name, bool httpEquiv = false, int? timeoutMs = null` | `Task<string>` | Read a `<meta>` tag's `content` by `name` or `http-equiv` — avoids CSS selector quoting issues. |
| `GetSelectState(selector)` | `string selector` | `Task<Dictionary<string, object>>` | Read back actual DOM state of a select: `value`, `selectedIndex`, `selectedText`, `tagName`. |

**PressKey supported keys:** `Tab`, `Enter`, `Escape`, `Space`, `Backspace`, `Delete`, `ArrowUp`, `ArrowDown`, `ArrowLeft`, `ArrowRight`, `Home`, `End`, `PageUp`, `PageDown`, `F1`-`F12`, plus any single character (`a`, `1`, etc.).

**PressKey modifiers:** `"Shift"`, `"Control"` (or `"Ctrl"`), `"Alt"`, `"Meta"`.

```csharp
// CSS selectors (still work as before -- now with auto-waiting)
await Click("#submit-btn");
await Type("#email", "test@example.com");
await Select("#country", "us");
await Hover("#tooltip-trigger");

// Keyboard navigation
await PressKey("Tab");                                          // Move focus to next element
await PressKey("Tab", modifiers: new[] { "Shift" });            // Move focus backwards
await PressKey("Enter", "#submit-btn");                         // Press Enter on specific element
await PressKey("Escape");                                       // Close dialog
await PressKey("ArrowDown", "#dropdown");                       // Navigate dropdown
await PressKey("a", modifiers: new[] { "Control" });            // Ctrl+A (select all)

// Verify selection actually stuck (useful for custom web components)
var state = await GetSelectState("#country");
Assert.Equal("us", state["value"]?.ToString(), "Country selected");

// Shadow-piercing selectors work in all methods
await Click("ids-toolbar >>> [data-action='save']");
await Type("ids-input >>> input", "Hello");

// Contenteditable (rich text editor) support
await Type("[contenteditable]", "Hello world");                  // Plain text
await Type("[contenteditable]", "", html: "<b>Bold</b> text");   // Rich HTML
```

---

### Text Search (Find)

Search all visible text on the page. Returns matches with surrounding context, nearest CSS selector, and bounding rect. Useful for verifying non-interactive content (status messages, table cells, error text).

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `FindText(query, caseSensitive?, isRegex?, scrollTo?, highlight?, visibleOnly?)` | `string query, bool caseSensitive = false, bool isRegex = false, int? scrollTo = null, bool highlight = false, bool visibleOnly = true` | `Task<Dictionary<string, object>>` | Search page text. By default only visible text (filters out hidden/off-screen elements). Returns `matchCount` and `matches[]` with `matchText`, `context`, `selector`, `tag`, `rect`. |
| `ClearFindHighlights()` | *(none)* | `Task` | Remove all highlights added by `FindText` with `highlight: true`. |

```csharp
// Find text on the page
var result = await FindText("Order confirmed");
Log($"Found {result["matchCount"]} matches");

// Find with regex and highlight
var result = await FindText("Error.*timeout", isRegex: true, highlight: true);

// Find and scroll to first match
await FindText("Order confirmed", scrollTo: 0);

// Clean up highlights
await ClearFindHighlights();
```

---

## Semantic Locators

Locators find elements by meaning rather than DOM structure. They're more resilient to UI refactors (class name changes, restructured markup, etc.) because they target what the user sees.

### Locator Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `ByRole(role, name?)` | `string role, string? name = null` | `string` | Find by ARIA role and optional accessible name |
| `ByLabel(text)` | `string text` | `string` | Find input/select/textarea by associated label text |
| `ByText(text)` | `string text` | `string` | Find element by visible text content (case-insensitive, whitespace-normalized) |
| `ByPlaceholder(text)` | `string text` | `string` | Find input by placeholder text |
| `ByTestId(testId)` | `string testId` | `string` | Find element by `data-testid` attribute |
| `ByFrame(frame, selectorOrLocator)` | `string frame, string selectorOrLocator` | `string` | Scope a selector/locator to a same-origin iframe (`frameId`, iframe `name`, or CSS of `<iframe>`) |

Locators return special strings that all action methods understand. Pass them directly to `Click`, `Type`, `GetText`, etc.

```csharp
await Click(ByFrame("child", "#in-frame"));
await Type(ByFrame("f1", ByLabel("Email")), "a@b.c");
await Drag("#src", "#dst", steps: 10);
var dl = await WaitForDownload(fileNameContains: "report");
// DownloadEntry C# names: Id, Url, SuggestedFileName, Path, State, BytesReceived, TotalBytes, MimeType, Timestamp
// Friendly aliases: Bytes / ByteCount, Mime, FileName (REST JSON uses bytes / mime)
AssertDownload(fileNameContains: "report", minBytes: 1, entry: dl);
Console.WriteLine($"{dl.FileName}: {dl.Bytes} bytes, mime={dl.Mime}");
await SetEmulation(new EmulationUpdate { ColorScheme = "dark", Locale = "sv-SE" });
StartTrace();
// ... actions ...
StopTrace();
var har = ExportHar(includeBodies: false);
```

### Usage

```csharp
// By ARIA role + accessible name
await Click(ByRole("button", "Submit"));
await Click(ByRole("link", "Sign in"));
await Type(ByRole("textbox", "Email"), "user@example.com");
var heading = await GetText(ByRole("heading"));

// By label (associated <label>, aria-label, aria-labelledby, etc.)
await Type(ByLabel("Email address"), "user@example.com");
await Select(ByLabel("Country"), "us");
await Click(ByLabel("Accept terms"));

// By visible text content
await Click(ByText("Sign in"));
await Click(ByText("Cancel"));

// By placeholder
await Type(ByPlaceholder("Search..."), "query");

// By test ID (data-testid attribute)
await Click(ByTestId("submit-btn"));
var title = await GetText(ByTestId("page-title"));
```

### Supported Roles

`button`, `link`, `textbox`, `checkbox`, `radio`, `combobox`, `option`, `heading`, `img`, `list`, `listitem`, `navigation`, `tab`, `tabpanel`, `dialog`, `alert`, `menu`, `menuitem`, `switch`, `slider`, `progressbar`, `region`, `form`, `table`, `row`, `cell`, `banner`, `contentinfo`, `main`, `search`, `separator`, `status`, `tooltip`.

Roles resolve to both implicit HTML roles (e.g. `<button>` for `"button"`, `<a href>` for `"link"`) and explicit `role="..."` attributes.

### Accessible Name Resolution

When you use `ByRole("button", "Submit")` or `ByLabel("Email")`, Trowser checks multiple sources for the element's accessible name, in order:

1. `aria-label` attribute
2. `aria-labelledby` reference
3. `<label for="id">` association
4. `label` attribute (common in Web Components like IDS, Shoelace)
5. Wrapping `<label>` element text
6. `innerText` / `textContent`
7. `value` (for submit/button inputs)
8. `placeholder`
9. `title`

### Locators + Auto-Waiting

Locators integrate with auto-waiting. When you write:

```csharp
await Click(ByRole("button", "Submit"));
```

Trowser will:
1. Search the DOM (including shadow roots) for a button with accessible name "Submit"
2. If not found, retry every 100ms for up to 5000ms (default timeout)
3. Once found, check that it's visible and enabled
4. Click it

This means you don't need separate `WaitForElement` calls when using locators -- the wait is built in.

---

## Scrolling

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `Scroll(selector?, direction, scrollIntoView)` | `string? selector = null, string direction = "down", bool scrollIntoView = false` | `Task` | Scroll page or element. |

**Directions:** `up`, `down` (one viewport height), `top`, `bottom` (full extent).

When no selector is specified, Trowser auto-detects the primary scrollable container: it checks the document first, then semantic elements (`<main>`, `[role="main"]`), then falls back to any element with `overflow-y: auto/scroll`.

```csharp
await Scroll(direction: "down");                           // Auto-detect scrollable area
await Scroll(direction: "top");                            // Scroll to top
await Scroll("#my-element", scrollIntoView: true);         // Scroll element into center of viewport
await Scroll("main", direction: "bottom");                 // Scroll a specific container to bottom
```

---

## Element Inspection

These methods **pierce shadow DOM** -- they find elements inside Web Component shadow roots. They support shadow-piercing selectors with `>>>` notation and also automatically search all shadow roots for regular selectors.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `GetText(selector)` | `string selector` | `Task<string>` | Inner text. Searches shadow DOM. Throws if not found. |
| `GetAttribute(selector, attr)` | `string selector, string attribute` | `Task<string>` | HTML attribute value. Searches shadow DOM. Throws if not found. |
| `GetProperty(selector, prop)` | `string selector, string property` | `Task<string>` | Live DOM property value (e.g. `value`, `checked`, `selectedIndex`). Unlike `GetAttribute`, reads the current state managed by JS frameworks. |
| `IsChecked(selector)` | `string selector` | `Task<bool>` | Whether a checkbox/toggle is checked. Reads the live DOM `checked` property. |
| `Exists(selector)` | `string selector` | `Task<bool>` | Whether element exists (including shadow DOM). **Never throws.** **No auto-wait** — unlike Click, GetText, etc., Exists checks immediately. After navigation or AJAX, call `WaitForElement` first, or Exists may return false for elements that are still loading. |
| `Count(selector)` | `string selector` | `Task<int>` | Number of matching elements (including shadow DOM). Returns 0 if none. |
| `Extract(selector, fields...)` | `string selector, params (string, string)[] fields` | `Task<List<Dictionary<string, string>>>` | Extract structured data from repeating elements. See below. |
| `Extract(selector, fields, limit)` | `string selector, Dictionary<string, string>? fields, int limit = 0` | `Task<List<Dictionary<string, string>>>` | Extract with explicit field dictionary and optional limit. |

**Extract** extracts structured data from repeating page elements into a list of dictionaries:

- **Table auto-extract:** Pass a `<table>` selector — columns are named from `<th>` headers automatically.
- **Field mapping:** Pass a container selector + field tuples `("fieldName", "subSelector")` to extract specific child elements.
- **Simple list:** Pass just a selector with no fields — returns `[{text: "..."}]` for each match.

Append `@attr` to a sub-selector to extract an attribute instead of text (e.g., `"a@href"`, `"img@src"`). Use `"."` to target the container element itself, or `"@attr"` for the container's attribute.

```csharp
// Auto-extract a table (column headers become field names)
var rows = await Extract("table.products");
// → [{Name: "Widget A", Price: "$9.99"}, {Name: "Widget B", Price: "$19.99"}]

// Extract with field mapping (sub-selectors within each container)
var products = await Extract(".product-card", ("name", "h3"), ("price", ".price"), ("url", "a@href"));
// → [{name: "Widget A", price: "$9.99", url: "/products/a"}, ...]

// Simple text extraction from a list
var items = await Extract("ul.results li");
// → [{text: "Result 1"}, {text: "Result 2"}, ...]

// With limit
var top5 = await Extract("table.data", null, limit: 5);
```

```csharp
var text = await GetText("h1");
var href = await GetAttribute("a.main", "href");
var inputValue = await GetProperty("#email", "value");      // live value from Angular/React/Vue
var isChecked = await IsChecked("#terms-checkbox");          // checkbox state
var exists = await Exists("#login-form");
var count = await Count(".result-item");
```

---

## Waiting

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `WaitForElement(selector, timeoutMs?)` | `string, int = 10000` | `Task` | Wait until element appears. Throws `TimeoutException`. |
| `WaitForRequest(urlSubstring, timeoutMs?)` | `string, int = 10000` | `Task<NetworkEntry>` | Wait for matching network request. Uses **plain substring** matching (case-insensitive), not glob. Pass `"/api/users"` to match any URL containing that string. Do not use `*pattern*` — asterisks are literal and will not match. Throws `TimeoutException`. |
| `WaitForRequest(urlSubstring, method?, status?, timeoutMs?)` | `string, string?, int?, int = 10000` | `Task<NetworkEntry>` | Wait for matching network request with optional method and status filters. Example: `await WaitForRequest("/api/save", "POST", 200, 5000)`. |
| `WaitForNavigation(timeoutMs?)` | `int = 10000` | `Task<bool>` | Wait for a single page navigation event. Returns true if navigated, false on timeout. |
| `WaitForFinalNavigation(quietPeriodMs?, timeoutMs?)` | `int = 500, int = 15000` | `Task<int>` | Wait for a chain of navigations to settle (redirect chains, SAML POST, OAuth). Returns the number of navigations observed. |
| `WaitForIdle(quietPeriodMs?, timeoutMs?)` | `int = 500, int = 10000` | `Task<bool>` | Wait until network is quiet and CSS animations stop. Returns true if idle, false on timeout. |
| `Sleep(ms)` | `int ms` | `Task` | Pause execution. |

```csharp
await WaitForElement("#content");
await WaitForElement(".results", 30000);

await Click("a.next-page");
var navigated = await WaitForNavigation(5000);

// Wait for redirect chains (SAML, OAuth, SSO)
await Click(ByRole("button", "LOGIN WITH POST"));
var navCount = await WaitForFinalNavigation(500, 15000);
Log($"Navigated {navCount} times, landed on: {await GetCurrentUrl()}");

var entry = await WaitForRequest("/api/data");
Assert.Equal(200, entry.StatusCode);

// Wait for a specific POST request with expected status
await Click("#save-btn");
var saved = await WaitForRequest("/api/save", "POST", 200, 5000);
Assert.Equal("POST", saved.Method);

// Wait for page to fully settle (network quiet for 500ms + no animations)
await Click("#load-more");
var idle = await WaitForIdle(500, 10000);

await Sleep(2000);
```

---

## JavaScript Execution

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `ExecuteJs(script, timeoutMs?)` | `string script, int timeoutMs = 30000` | `Task<string>` | Execute JavaScript and return the result as a string. **Awaits Promises** (async/await, fetch, .then). Multi-statement scripts and any script with top-level `return` are auto-wrapped in an IIFE; single expressions like `document.title` run as-is. |

```csharp
var result = await ExecuteJs("document.title");
var result2 = await ExecuteJs("return document.title");  // auto-wrapped
var count = await ExecuteJs("document.querySelectorAll('a').length.toString()");
var links = await ExecuteJs("""
    var nodes = document.head.querySelectorAll('link');
    var out = [];
    for (var i = 0; i < nodes.length; i++) out.push(nodes[i].href);
    return JSON.stringify(out);
    """);  // multi-statement + return — auto-wrapped
var body = await ExecuteJs("(async () => { var r = await fetch('/api/users'); return await r.text(); })()");
```

---

## Test Data

Random test strings and security payloads for form fields, JSON parameters, URLs, and similar inputs. Managed via **Test Data…** (Ctrl+D) in the GUI; data files `test_strings.json` and `test_payloads.json` live next to `Trowser.exe`.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `GetRandomTestData(kind?)` | `string? kind = null` | `Task<string?>` | Random entry from the active collection, or from `strings` / `payloads` when `kind` is set. Respects **Online** and **ASCII only** from the Test Data dialog (online applies to strings only). Returns `null` when the collection is empty. |

```csharp
// Use whichever tab is active in the Test Data dialog
var data = await GetRandomTestData();
if (data != null)
    await Type("#search", data);

// Explicit security payload (XSS, SQLi, SSRF, path traversal, etc.)
var payload = await GetRandomTestData("payloads");
if (payload != null)
    await Type("#comment", payload);

// General test string (unicode, edge cases, etc.)
var testString = await GetRandomTestData("strings");
```

**REST equivalent:** `GET /api/test-data?kind=strings|payloads` — **MCP:** `browser_test_data`.

---

## Browser Fetch (API Testing)

Send HTTP requests directly from the browser context using `fetch()`. Includes the page's cookies, auth tokens, and session state automatically. Relative URLs resolve against the current page origin. Unlike `ExecuteJs` with manual `fetch()`, this returns a structured result.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `Fetch(url, method?, headers?, body?, timeoutMs?, redirect?)` | `string url, string method = "GET", Dictionary<string, string>? headers = null, string? body = null, int timeoutMs = 30000, string? redirect = null` | `Task<string>` | Execute fetch() in the browser context. Returns JSON string with `ok`, `status`, `statusText`, `redirected`, `type`, `url`, `headers`, `body`. Set `redirect` to `"manual"` to capture 3xx without following (SAML/OAuth/open-redirect testing). |
| `FetchBatchAsync(requests, concurrent?)` | `IReadOnlyList<FetchBatchRequestItem> requests, bool concurrent = true` | `Task<IReadOnlyList<FetchBatchResultItem>>` | Multiple fetch() calls; set `concurrent` to fire in parallel for race testing. Each item supports `Redirect` property. |
| `GetCookieHeaderForUrl(absoluteUrl)` | `string absoluteUrl` | `Task<string>` | Cookie header value for the URL from the WebView jar (HttpOnly included). Use with server-side tools that need session cookies. |

```csharp
// Simple GET
var result = await Fetch("/api/health");
Log(result);  // JSON: {"ok":true,"status":200,"statusText":"OK","headers":{...},"body":"..."}

// POST with JSON body
var response = await Fetch("/api/users", "POST",
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/json" },
    body: "{\"name\": \"Alice\", \"email\": \"alice@example.com\"}");

// Parse the response
var doc = System.Text.Json.JsonDocument.Parse(response);
var status = doc.RootElement.GetProperty("status").GetInt32();
var responseBody = doc.RootElement.GetProperty("body").GetString();
Assert.Equal(201, status, "User created");
Assert.Contains("Alice", responseBody, "Response contains user name");

// PUT to update a resource
var updated = await Fetch("/api/users/42", "PUT",
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/json" },
    body: "{\"name\": \"Updated\"}");

// DELETE
var deleted = await Fetch("/api/users/42", "DELETE");

// With custom timeout
var slow = await Fetch("/api/slow-endpoint", timeoutMs: 60000);

// Capture redirect without following (open-redirect / SAML / OAuth testing)
var redirect = await Fetch("/login/redirect", redirect: "manual");
var rdDoc = System.Text.Json.JsonDocument.Parse(redirect);
var rdStatus = rdDoc.RootElement.GetProperty("status").GetInt32();
var rdType = rdDoc.RootElement.GetProperty("type").GetString(); // "opaqueredirect"
Log($"Redirect captured: {rdStatus}, type={rdType}");

// Parallel authenticated requests (race / ordering tests)
var batch = new List<FetchBatchRequestItem>
{
    new() { Url = "/api/a", Method = "GET" },
    new() { Url = "/api/b", Method = "GET" }
};
var batchResults = await FetchBatchAsync(batch, concurrent: true);
```

---

## Peer sessions & BOLA / authz comparison

Cross-identity testing uses additional Trowser instances (peers) on localhost. In the GUI, open **More → Peer sessions** to launch peers and log in as different users. Scripts share the same `PeerRegistry` as the REST API.

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `RegisterPeer` | `(string name, string baseUrl, string? apiKey = null)` | `void` | Register a peer instance (`baseUrl` must be localhost, e.g. `http://127.0.0.1:6924`). |
| `PeerFetch` | `(string peerName, string url, string method = "GET", Dictionary<string, string>? headers = null, string? body = null, int timeoutMs = 30000)` | `Task<string>` | HTTP request through a peer's session (via peer `/api/fetch-direct`). Returns raw JSON response wrapper. |
| `AuthzDiff` | `(string[] peers, object[] endpoints, bool includeBodyOnMismatch = true, bool ensureOrigin = false)` | `Task<List<AuthzComparisonResult>>` | Compare driver session vs each peer. Endpoints may be URL strings or `{ url, method?, headers?, body? }`. Verdicts include `BOLA_SUSPECTED`, `FILTERED_RESPONSE`, `PROPERLY_DENIED`. |
| `LaunchPeer` | `(string name, int? port = null, string? apiKey = null, string? sessionName = null)` | `Task` | Launch a peer Trowser process (**GUI only**). |
| `GetPeerNamesForTests` | `()` | `IReadOnlyList<string>` | Alive peer names marked "Use for tests" in Peer sessions dialog. |

```csharp
// Quicktest: Resources/Quicktests/Security/BolaAcrossSessions.csx

RegisterPeer("peer1", "http://localhost:6924", "trowser_...");
var results = await AuthzDiff(
    new[] { "peer1" },
    new object[] { "https://app.example/api/me", new { url = "https://app.example/api/orders", method = "PUT", body = "{\"id\":1}" } });

foreach (var r in results)
    foreach (var c in r.Comparisons)
        Log($"[{c.Finding}] {c.Method} {c.Url}", c.Finding == "BOLA_SUSPECTED" ? "#F44747" : "#4EC9B0");
```

GUI workflow: **Script Console → Endpoints → Peer →** on a captured request, launch peers, log in, **Test BOLA**. Results appear in the script console with verdict colors.

---

## Screenshots & Logging

```csharp
await Screenshot("screenshots/homepage.png");
Log("Starting test...");
Log($"Found {count} items");
```

---

## Test Assertions (`Assert.*`)

Assertions **log pass/fail** but **do not throw**. Script continues after every assertion. Summary auto-printed at end.

### Assertion Methods

| Method | Signature | Checks |
|--------|-----------|--------|
| `Assert.True` | `(bool condition, string? message)` | condition is `true` |
| `Assert.False` | `(bool condition, string? message)` | condition is `false` |
| `Assert.Equal` | `(T expected, T actual, string? message)` | `expected` equals `actual` |
| `Assert.NotEqual` | `(T expected, T actual, string? message)` | values differ |
| `Assert.Contains` | `(string substring, string actual, string? message)` | `actual` contains `substring` |
| `Assert.NotContains` | `(string substring, string actual, string? message)` | `actual` does not contain `substring` |
| `Assert.Matches` | `(string pattern, string actual, string? message)` | `actual` matches regex |
| `Assert.Null` | `(object? value, string? message)` | value is `null` |
| `Assert.NotNull` | `(object? value, string? message)` | value is not `null` |
| `Assert.NotEmpty` | `(string? value, string? message)` | string is not null or empty |
| `Assert.GreaterThan` | `(double expected, double actual, string? message)` | `actual > expected` |
| `Assert.LessThan` | `(double expected, double actual, string? message)` | `actual < expected` |
| `Assert.CountEquals` | `(int count, IEnumerable<T> collection, string? message)` | collection has exactly `count` items |
| `Assert.Pass` | `(string message)` | Unconditional pass |
| `Assert.Fail` | `(string message)` | Unconditional fail |
| `Assert.Section` | `(string name)` | Start a named test section. Groups subsequent assertions in the summary. |
| `Assert.Summary()` | | Print summary (with per-section breakdown). Auto-called at script end. |
| `Assert.Reset()` | | Clear all results and current section. |

### Page Text Assertions

Top-level async methods that check whether text appears anywhere in the visible page content. These use `document.body.innerText` (visible text only, not HTML).

| Method | Parameters | Returns | Checks |
|--------|------------|---------|--------|
| `AssertPageContains` | `string expectedText, string? message` | `Task` | Page visible text contains `expectedText` |
| `AssertPageNotContains` | `string unexpectedText, string? message` | `Task` | Page visible text does NOT contain `unexpectedText` |

```csharp
await AssertPageContains("Welcome back");
await AssertPageNotContains("Error: something went wrong");

// Or use GetPageText() for custom checks
var pageText = await GetPageText();
Assert.Contains("Welcome", pageText, "Has welcome message");
Assert.Matches(@"Order #\d+", pageText, "Shows order number");

// Hidden strings and screen-reader-only labels (REST: GET /api/page-text/all, GET /api/page-text/screen-reader)
var allSegments = await GetAllPageText();
var srOnly = await GetScreenReaderTexts();
```

---

## Accessibility (WCAG)

Powered by axe-core 4.10.3.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertAccessible` | `string? wcagLevel = "AA", Impact? minImpact = null, string? message = null` | `Task` |
| `CheckAccessibility` | `string? wcagLevel = "AA", string? selector = null` | `Task<AccessibilityResult>` |
| `PrintAccessibilityReport` | `string? wcagLevel = "AA", bool includeNodes = true, Impact? minImpact = null` | `Task<AccessibilityResult>` |

**WCAG levels:** `"A"`, `"AA"` (default), `"AAA"`, or `null` for all rules.

**Impact enum:** `Impact.Minor`, `Impact.Moderate`, `Impact.Serious`, `Impact.Critical`

**AccessibilityResult:** `Violations`, `Passes`, `Incomplete`, `ViolationCount`, `PassCount`, `AffectedElementCount`, `IsClean`, `GetCritical()`, `GetByMinImpact(Impact)`, `GetByWcagLevel(string)`, `Format(includeNodes?, minImpact?)`

**AccessibilityViolation:** `RuleId`, `Impact`, `Description`, `Help`, `HelpUrl`, `Tags`, `Nodes`, `Count`, `WcagLevel`, `WcagCriteria`

```csharp
await AssertAccessible("AA");
await AssertAccessible("AA", minImpact: Impact.Serious);

var results = await CheckAccessibility("AA");
foreach (var v in results.Violations)
    Log($"[{v.Impact}] {v.RuleId}: {v.Help} ({v.Count} elements)");

var critical = results.GetCritical();
Assert.Equal(0, critical.Count, "No critical a11y violations");
```

---

## Tab Order (Keyboard)

Verifies keyboard tab order with **real Tab and Shift+Tab** (CDP), like a user. Auto-detects **modal dialogs** (`aria-modal`, `<dialog open>`, popover) and scopes the walk to them — Tab reaching the page background while a modal is open is reported as **`modal-focus-leak`**.

| Method | Parameters | Returns |
|--------|------------|---------|
| `CheckTabOrder` | `TabOrderOptions? options = null` | `Task<TabOrderResult>` |
| `PrintTabOrderReport` | `TabOrderOptions? options = null, bool includeSteps = true` | `Task<TabOrderResult>` |
| `AssertTabOrderClean` | `TabOrderOptions? options = null, string? message = null` | `Task` |
| `AssertTabOrder` | `IReadOnlyList<string> expectedOrder, TabOrderOptions? options = null, string? message = null` | `Task` |

**TabOrderOptions:** `Selector`, `StartSelector`, `AutoDetectScope` (default true), `StrictScope` (default true), `MaxSteps` (default 150), `CheckPositiveTabIndex`, `CheckSkipped`, `CheckReadingOrder`, `CheckFocusTrap`, `CheckShiftTabConsistency`, `ExpectedOrder`

**TabOrderResult:** `FocusContextKind`, `FocusContextLabel`, `ScopeAutoDetected`, `ForwardSteps`, `BackwardSteps`, `Issues`, `ShiftTabConsistent`, `Format(includeSteps?)`

**Issue categories:** `modal-focus-leak`, `focus-escaped-scope`, `skipped-focusable`, `focus-trap`, `shift-tab-inconsistency`, `positive-tabindex`, `reading-order`, `expected-order-mismatch`, `incomplete-cycle`, `no-focusables`

Steps marked **`[OUT OF SCOPE]`** landed outside the active context (critical under modals).

```csharp
// Auto-detect modal and audit only inside it
var result = await CheckTabOrder(new TabOrderOptions { AutoDetectScope = true, StrictScope = true });
Assert.Equal(0, result.Issues.Count(i => i.Category == "modal-focus-leak"));

// Full page with real Tab walk
await AssertTabOrderClean();
```

**REST:** `POST /api/tab-order` — same options as JSON body.

**MCP:** `browser_tab_order`

---

## Performance (Web Vitals)

Measures Core Web Vitals and page performance using browser Performance APIs.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertPerformance` | `string? message = null` | `Task` |
| `AssertPerformanceMetric` | `string metricName, double maxValue, string? message = null` | `Task` |
| `CheckPerformance` | (none) | `Task<PerformanceResult>` |
| `PrintPerformanceReport` | `bool includeNavigation = true, bool includeResources = true` | `Task<PerformanceResult>` |

**PerformanceRating enum:** `PerformanceRating.Good`, `PerformanceRating.NeedsImprovement`, `PerformanceRating.Poor`

**PerformanceResult:** `Metrics`, `Navigation`, `Resources`, `IsGood`, `HasPoorMetrics`, `GetMetric(name)`, `GetCoreWebVitals()`, `GetByRating(rating)`, `Format(includeNavigation?, includeResources?)`

**WebVitalMetric:** `Name`, `FullName`, `Value`, `Unit`, `Rating`, `Element`

**Metric thresholds** (Google Core Web Vitals):

| Metric | Good | Needs Improvement | Poor |
|--------|------|-------------------|------|
| LCP | <= 2500ms | <= 4000ms | > 4000ms |
| CLS | <= 0.1 | <= 0.25 | > 0.25 |
| INP | <= 200ms | <= 500ms | > 500ms |
| TTFB | <= 800ms | <= 1800ms | > 1800ms |
| FCP | <= 1800ms | <= 3000ms | > 3000ms |

```csharp
await AssertPerformance();

await AssertPerformanceMetric("LCP", 2500, "LCP under 2.5s");
await AssertPerformanceMetric("TTFB", 800, "TTFB under 800ms");

var results = await CheckPerformance();
foreach (var m in results.Metrics)
    Log($"[{m.Rating}] {m.Name}: {m.Value}{m.Unit}");

var poor = results.GetByRating(PerformanceRating.Poor);
Assert.Equal(0, poor.Count, "No poor performance metrics");

var lcp = results.GetMetric("LCP");
if (lcp != null) Log($"LCP element: {lcp.Element}");
```

---

## Security endpoints vs scripting

[trowser-api-index.md](trowser-api-index.md) lists the full **security** surface: CVE scan, headers, CORS, XSS, mixed content, source maps, cookies, storage, discovery, HTTP methods, attack surface, SAML decode/capture/replay, Security Shadow, OOB callbacks, firewall-test, trace-input, CSRF, fuzz, interrupter, third-party inventory, and more.

**This guide** documents **C# script helpers** where they exist (Retire.js, headers, CORS, XSS, mixed content, cookies, source maps, tech stack detection, third-party inventory, web storage, path discovery, HTTP methods, attack surface map, SAML decode-from-log, auto-scan pipeline, secrets harvest, **injection scanners (SQLi / XSS / SSTI / SSRF)**, **firewall-test, JWT analysis, OIDC provider analysis, GraphQL analysis, JavaScript static audit (`js-audit`), HTTP smuggling**, **security playbooks (Trowser Twelve)**). Operations that require **`safetyMode: "active"`** on the REST API but have script helpers bypass the safety gate automatically in scripting (same as auto-scan / secrets harvest / fuzz / interrupter). Other `safetyMode: "active"` operations **without** script helpers (trace-input, CSRF validation, SAML replay, monkey tests) and **Settings / MCP-first** flows (Security Shadow, callback watcher) are intended for the REST API or MCP tools — see the small reference for request shapes.

**Unified findings:** `RunSqliScan`, `RunXssScan`, `RunSstiScan`, and `RunSsrfScan` (via API mapping) emit `UnifiedSecurityFinding` / `SecurityScanResult` — same fields as REST/MCP (`severity`, `confidence`, `tier`, `endpoint`, `param`, `payload`, `evidence`, `proofHint`, `nextActions`). Call `.ToSecurityScanResult()` / `.ToApiResponse()` when you want the JSON envelope shape.

---

## Security playbooks (Trowser Twelve orchestration)

Runs a **category playbook** via the in-process orchestration engine (same engine as `POST /api/orchestrate/{id}`). Each playbook chains the relevant security scanners for one OWASP-style category and returns a VPX-backed markdown report. The **Trowser Twelve** quicktests in **Quicktests → Security → Trowser Twelve** call these helpers directly from C# — no REST API server required.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunPlaybookAsync` | `string playbookId, string safetyMode = "safe", string depth = "standard", string format = "markdown", string? host = null, int maxSeconds = 120, int maxRequests = 800, CancellationToken ct = default` | `Task<PlaybookResponse>` |
| `PrintPlaybookReport` | Same as `RunPlaybookAsync` but `format` is fixed to `"markdown"` and output is colorized to the script console | `Task<PlaybookResponse>` |
| `AssertPlaybookClean` | `string playbookId, string safetyMode = "safe", string depth = "standard", string? minSeverity = "medium", string? message = null, string? host = null, CancellationToken ct = default` | `Task` |

**Playbook IDs:**

| ID | Category |
|----|----------|
| `full` | Full site assessment (all categories + chain correlation) |
| `a01-access` | Access control / IDOR / authz |
| `a02-misconfig` | Misconfiguration (headers, CORS, cookies, discovery) |
| `a03-supplychain` | Supply chain (Retire.js, manifests, CI/CD exposure) |
| `a04-crypto` | Cryptography & secrets |
| `a05-injection` | Injection full (SQLi, XSS, SSTI, CSTI, etc.; ~1800s) |
| `a05a-injection-core` | Injection core for agents (cmd + XSS + SQLi; ~300s) |
| `a05b-injection-templates` | SSTI / NoSQL / LDAP / path |
| `a05c-injection-advanced` | Login-sweep / deser / upload / parser |
| `a06-design` | Insecure design |
| `a07-authn` | Authentication |
| `a09-opsec` | Operational security |
| `a11-ssrf` | SSRF |
| `a12-availability` | Availability / DoS indicators |
| `a13-llm` | AI / LLM risks |
| `a14-other` | Other / catch-all |

**Safety modes:** `passive` (network log only), `safe` (default — no write verbs), `active` (injection/fault probes), `aggressive`. Use `active` when you need live SQLi, fuzz, or replay steps inside a playbook.

**PlaybookResponse:** `PlaybookId`, `RunId`, `SafetyMode`, `Depth`, `StepsExecuted`, `BudgetUsed`, `Warnings`, `AssertionsAdded`, `NextActions`, `Markdown` (when format is markdown), `CorrelatedChains` (full playbook only).

**NextAction:** `Action` (`verify-workflow`, `run-playbook`, `manual-check`), `WorkflowId`, `PlaybookId`, `Rationale`.

Browse the target application first so the network log is populated. For the full-site run, increase budget:

```csharp
// One category — safe mode (default)
await PrintPlaybookReport("a05-injection");

// Full site with extended budget
var result = await PrintPlaybookReport("full",
    safetyMode: "safe",
    depth: "standard",
    maxSeconds: 600,
    maxRequests: 2000);

foreach (var action in result.NextActions)
    Log($"→ {action.Action}: {action.Rationale}");

// Assertion wrapper (uses vpx-compact internally)
await AssertPlaybookClean("a02-misconfig", minSeverity: "high");

// Active mode for live injection probes inside the playbook
await RunPlaybookAsync("a05-injection", safetyMode: "active", format: "vpx-compact");
```

REST equivalents: `POST /api/orchestrate/{id}`, dry-run at `POST /api/orchestrate/dry-run/{id}`, catalog at `GET /api/orchestrate/playbooks`. See **trowser-api-reference.md** under **Orchestration**.

---

## Security (Retire.js)

Scans for JavaScript libraries with known CVE vulnerabilities using the Retire.js vulnerability database.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertSecure` | `Severity? minSeverity = null, string? message = null` | `Task` |
| `CheckSecurity` | (none) | `Task<SecurityResult>` |
| `PrintSecurityReport` | `bool includeDetails = true, bool checkForUpdates = true` | `Task<SecurityResult>` |
| `CheckSecurityUpdates` | (none) | `Task<RepositoryUpdateInfo>` |

**Severity enum:** `Severity.Low`, `Severity.Medium`, `Severity.High`, `Severity.Critical`

**SecurityResult:** `Libraries`, `Vulnerable`, `LibraryCount`, `VulnerableCount`, `VulnerabilityCount`, `IsClean`, `GetCritical()`, `GetByMinSeverity(severity)`, `Format(includeDetails?)`

**DetectedLibrary:** `Name`, `Version`, `DetectionMethod`, `Vulnerabilities`, `IsVulnerable`, `HighestSeverity`

**LibraryVulnerability:** `Severity`, `Summary`, `CVEs`, `CWEs`, `Info`, `Below`, `AtOrAbove`

**RepositoryUpdateInfo:** `UpdateAvailable`, `Source`, `CurrentDate`, `LatestDate`, `LocalPath`, `DownloadUrl`, `Error`

**Updating the vulnerability database:** The vulnerability database is bundled at build time. To use a newer version, download the latest `jsrepository.json` from the Retire.js GitHub repository and place it next to the Trowser executable. `PrintSecurityReport` will notify you when a newer version is available on GitHub.

```csharp
await AssertSecure();
await AssertSecure(minSeverity: Severity.High, message: "No high/critical CVEs");

var results = await CheckSecurity();
foreach (var lib in results.Libraries)
    Log($"{lib.Name} {lib.Version} -- {(lib.IsVulnerable ? "VULNERABLE" : "OK")}");

var critical = results.GetCritical();
Assert.Equal(0, critical.Count, "No high/critical vulnerabilities");

// Check if a newer vulnerability database is available
var update = await CheckSecurityUpdates();
if (update.UpdateAvailable)
    Log($"New database available (latest: {update.LatestDate:yyyy-MM-dd})");
```

---

## Security Headers

Analyzes HTTP response headers for security misconfigurations based on OWASP best practices.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertSecurityHeaders` | `Severity? minSeverity = null, string? message = null` | `Task` |
| `CheckSecurityHeaders` | (none) | `Task<HeadersResult>` |
| `PrintSecurityHeadersReport` | `bool includeDetails = true` | `Task<HeadersResult>` |

**HeadersResult:** `Url`, `IsHttps`, `RawHeaders`, `Findings`, `FindingCount`, `IsClean`, `GetCritical()`, `GetByMinSeverity(severity)`, `Format(includeDetails?)`

**HeaderFinding:** `Header`, `Severity`, `Description`, `Recommendation`, `CurrentValue`, `Reference`

**Headers checked:**
- Content-Security-Policy (presence, unsafe-inline/unsafe-eval/wildcard in script-src)
- Strict-Transport-Security (HTTPS only; presence and max-age)
- X-Content-Type-Options (should be `nosniff`)
- X-Frame-Options / CSP frame-ancestors (clickjacking protection)
- Referrer-Policy (presence and unsafe values)
- Permissions-Policy (presence)
- Server / X-Powered-By / X-AspNet-Version (information disclosure)
- Deprecated headers (X-XSS-Protection enabled, Expect-CT, HPKP)

**False-positive avoidance:** HSTS is only checked on HTTPS pages. X-Frame-Options is not flagged if CSP frame-ancestors is set. `unsafe-inline` in `style-src` is not penalized. COOP/COEP/CORP are not checked.

```csharp
await AssertSecurityHeaders();
await AssertSecurityHeaders(minSeverity: Severity.High, message: "No high-severity header issues");

var result = await CheckSecurityHeaders();
foreach (var f in result.Findings)
    Log($"[{f.Severity}] {f.Header}: {f.Description}");

// Check specific headers from the raw response
if (result.RawHeaders.ContainsKey("content-security-policy"))
    Log($"CSP: {result.RawHeaders["content-security-policy"]}");
```

---

## CORS Configuration

Audits CORS configuration by probing the current page URL with various `Origin` headers. Detects reflected origins, wildcard policies, null origin acceptance, and subdomain/scheme attacks.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertCors` | `Severity? minSeverity = null, string? message = null` | `Task` |
| `CheckCors` | (none) | `Task<CorsResult>` |
| `PrintCorsReport` | `bool includeDetails = true` | `Task<CorsResult>` |

**CorsResult:** `Url`, `Findings`, `Issues` (findings with severity), `IssueCount`, `IsClean`, `Format(includeDetails?)`

**CorsFinding:** `Origin`, `Reflected`, `Wildcard`, `AllowOrigin`, `AllowCredentials`, `AllowMethods`, `AllowHeaders`, `Severity`, `Description`

**Probes tested:**
- Same-origin (baseline)
- Arbitrary third-party (`https://evil.com`)
- Null origin (sandboxed iframes, data: URIs)
- Subdomain attack (`attacker.target.com`)
- Scheme downgrade (`http://` for `https://` sites)
- Suffix attack (`target.com.evil.com`)

```csharp
await AssertCors();
await AssertCors(minSeverity: Severity.High, message: "No high-severity CORS issues");

var result = await CheckCors();
foreach (var f in result.Issues)
    Log($"[{f.Severity}] Origin {f.Origin}: {f.Description}");

// Check if credentials are exposed to arbitrary origins
var credentialLeaks = result.Issues.Where(f => f.AllowCredentials).ToList();
Assert.Equal(0, credentialLeaks.Count, "No credential exposure via CORS");
```

---

## Endpoint Discovery

Scans for hidden endpoints, admin panels, config files, and API documentation by probing common paths. Useful for reconnaissance during security testing.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertDiscover` | `string wordlist = "common", string basePath = "/", int delayMs = 0, string? message = null, bool spaMode = false, string? spaProbePath = null` | `Task` |
| `DiscoverEndpoints` | `string wordlist = "common", string basePath = "/", int delayMs = 0, bool spaMode = false, string? spaProbePath = null` | `Task<DiscoverResult>` |
| `PrintDiscoverReport` | `string wordlist = "common", string basePath = "/", bool includeDetails = true, int delayMs = 0, bool spaMode = false, string? spaProbePath = null` | `Task<DiscoverResult>` |

**DiscoverResult:** `BaseUrl`, `ScannedCount`, `Discovered`, `DiscoveredCount`, `SpaFilteredCount`, `SpaBaseline`, `Format(includeDetails?)`

**DiscoveredEndpoint:** `Path`, `StatusCode`, `ContentType`, `Title`, `ContentLength`, `RedirectLocation`

Set `spaMode` to `true` on single-page apps so responses that match the shell fingerprint (probe to a random invalid path) are excluded from `Discovered`. Uniform auth redirects (same 3xx + same IdP/login Location host+path, query stripped) are always filtered — Shibboleth/SAML/OIDC login gates no longer flood discoveries.

**Wordlists:**
- `"common"` (~50 paths) — robots.txt, .env, .git, admin, swagger, health, config files
- `"full"` (~150 paths) — Common + Docker files, CI/CD configs, backup archives, framework-specific paths
- `"api"` — API-focused: /api/v1, /graphql, /swagger, /openapi.json, OAuth endpoints

**`delayMs`:** Milliseconds to wait between each request. Default `0` (no delay) runs 10 requests in parallel for maximum speed. When `delayMs > 0`, requests run sequentially with the specified delay — useful to avoid `429 Too Many Requests` from rate-limited servers.

```csharp
// Assert no sensitive endpoints are accessible (appears in test summary)
await AssertDiscover();

// Quick scan with common paths
var result = await DiscoverEndpoints();
Log($"Found {result.DiscoveredCount} endpoints out of {result.ScannedCount} scanned");

foreach (var d in result.Discovered)
    Log($"  {d.StatusCode} {d.Path} [{d.ContentType}]");

// Full scan with detailed report
await PrintDiscoverReport(wordlist: "full");

// Scan an API subdirectory
await PrintDiscoverReport(wordlist: "api", basePath: "/api/");

// Slow scan to avoid 429 rate limiting (200ms between requests)
await PrintDiscoverReport(wordlist: "common", delayMs: 200);

// Assert no sensitive files are exposed
var sensitive = result.Discovered.Where(d =>
    d.StatusCode < 400 &&
    (d.Path.Contains(".env") || d.Path.Contains(".git") || d.Path.Contains("backup"))).ToList();
Assert.Equal(0, sensitive.Count, "No sensitive files publicly accessible");
```

---

## HTTP method probing (document URL)

Server-side probes (same as `POST /api/security/methods`): GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE. Flags **TRACE** returning 200 (XST risk) and **PUT**/**DELETE** returning 2xx (verify authorization). Does not use browser `fetch`; certificate validation is bypassed for the probe only (same as the REST API).

| Method | Parameters | Returns |
|--------|------------|---------|
| `CheckHttpMethods` | `string? url = null` | `Task<HttpMethodsSecurityResult>` |
| `PrintHttpMethodsReport` | `string? url = null, bool includeDetails = true` | `Task<HttpMethodsSecurityResult>` |
| `AssertHttpMethodsClean` | `string? url = null, string? message = null` | `Task` |

**HttpMethodsSecurityResult:** `Url`, `Results`, `AllowedMethods`, `SecurityIssues`, `SecurityIssueCount`, `Format(includeDetails?)`

---

## Attack surface (network log)

Summarizes endpoints, methods, parameters, auth hints, and response patterns from **captured** network entries (`POST /api/security/attack-surface`). If the log is empty, the report prints a short hint and returns an empty result.

`PrintAttackSurfaceReport` probes **RFC 9116 `security.txt`** only for the **current tab hostname** — not every host in the network log. Results appear at the **top** of `Format()` in `AttackSurfaceResult.SecurityTxt`. **`CheckAttackSurface`** does **not** run that probe.

| Method | Parameters | Returns |
|--------|------------|---------|
| `CheckAttackSurface` | `includeParameters = true, includeAuth = true, includeResponsePatterns = true, string? hostFilter = null, includeDataUrls = false` | `AttackSurfaceResult` |
| `PrintAttackSurfaceReport` | Same flags as `CheckAttackSurface`, plus `includeDetails = true` | `Task<AttackSurfaceResult>` |

**AttackSurfaceResult:** `Endpoints`, `Summary`, **`SecurityTxt`**, `Format(includeDetails?)` — see API reference (`securityTxt` / `checkSecurityTxt` on REST).

---
## SAML from network log

Passive decode of the latest SAML message in the log (`POST /api/security/saml-decode` with `source: network`). For **AssertSamlSecurity**, if no SAML is present, the assertion **passes** with “skipped” (useful in mixed flows).

| Method | Parameters | Returns |
|--------|------------|---------|
| `TryDecodeSamlFromNetwork` | `string? urlFilter = null` | `SamlDecodeResult?` |
| `PrintSamlFromNetworkReport` | `string? urlFilter = null, bool includeXml = false` | `Task<SamlDecodeResult?>` |
| `AssertSamlSecurity` | `Severity? minSeverity = null, string? urlFilter = null, string? message = null` | `Task` |

Replay and capture helpers (`SamlCapture` on the active tab, REST-only replay with `safetyMode: "active"`) are documented in **trowser-api-reference.md** under `/api/security/saml-capture` and `/api/security/saml-replay`.

---

## Auto-scan pipeline (attack surface → targeted scanners)

Discovers endpoints from **captured network traffic** (same as `CheckAttackSurface`), then automatically runs the **relevant** security scanners against them: **SQLi**, **IDOR**, **CSRF**, **path-traversal**, and **mass-assignment**. Each scanner only targets endpoints that match its requirements (e.g. SQLi needs query/body params, IDOR needs path params, mass-assignment needs JSON POST/PUT/PATCH). Browse the target application first to populate the network log.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunAutoScan` | `string? host = null, int maxEndpointsPerScanner = 5, int timeoutMs = 15000, bool includeSqli = true, bool includeIdor = true, bool includeCsrf = true, bool includePathTraversal = true, bool includeMassAssignment = true, string? minPriority = null` | `Task<AutoScanResult>` |
| `PrintAutoScanReport` | Same as `RunAutoScan`, plus `bool includeDetails = true` | `Task<AutoScanResult>` |
| `AssertAutoScanClean` | `string? host = null, int maxEndpointsPerScanner = 5, string? minSeverity = null, string? message = null` | `Task` |

**AutoScanResult:** `EndpointsDiscovered`, `EndpointsScanned`, `ScannersRun`, `ScannersSkipped`, `Findings`, `FindingsCount`, `IsClean`, `Errors`, `AttackSurfaceSummary`, `ElapsedMs`, `GetByMinSeverity(severity)`, `Format(includeDetails?)`

**AutoScanFinding:** `Scanner`, `Severity`, `Endpoint`, `Method`, `Title`, `Detail`

**`minPriority`:** Filter endpoints by attack-surface priority before scanning: `"low"` (default), `"medium"`, `"high"`, `"critical"`.

**`minSeverity`** (on `AssertAutoScanClean`): Only fail on findings at or above this severity: `"low"`, `"medium"`, `"high"`, `"critical"`.

```csharp
// Assert no vulnerabilities found across all scanners
await AssertAutoScanClean();

// Only fail on high/critical findings
await AssertAutoScanClean(minSeverity: "high");

// Scan a specific host only
await AssertAutoScanClean(host: "api.example.com");

// Full report
var result = await RunAutoScan(maxEndpointsPerScanner: 10);
Log($"Scanned {result.EndpointsScanned} endpoints with {string.Join(", ", result.ScannersRun)}");
Log($"Findings: {result.FindingsCount}");
foreach (var f in result.Findings)
    Log($"  [{f.Severity}] [{f.Scanner}] {f.Title} — {f.Endpoint}");

// Printed report with color
await PrintAutoScanReport(includeDetails: true);
```

---

## Secrets harvest (credential/secret exposure)

Unified **secret/credential harvesting** across all browser sources in one call: **JS bundles** (hardcoded credentials, API keys), **cookies & storage** (JWT tokens, auth tokens, PII), **network responses** (leaked credentials, bearer tokens), **visible page text** (debug output), and **source maps** (exposed `.map` files, debug mode). Returns **deduplicated**, **severity-prioritized** findings.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunSecretsHarvest` | `bool includeJsBundles = true, bool includeCookiesAndStorage = true, bool includeNetworkResponses = true, bool includePageText = true, bool includeSourceMaps = true, int maxJsScripts = 20, int maxNetworkResponses = 100, int timeoutMs = 30000` | `Task<HarvestResult>` |
| `PrintSecretsHarvestReport` | Same as `RunSecretsHarvest`, plus `bool includeDetails = true` | `Task<HarvestResult>` |
| `AssertSecretsClean` | `string? minSeverity = null, string? message = null` | `Task` |

**HarvestResult:** `Url`, `TotalFindings`, `Findings`, `IsClean`, `Summary`, `SourcesScanned`, `Errors`, `ElapsedMs`, `GetByMinSeverity(severity)`, `Format(includeDetails?)`

**SecretFinding:** `Source`, `Category`, `Severity`, `Location`, `Description`, `Snippet`

**HarvestSummary:** `Critical`, `High`, `Medium`, `Low`, `Info`, `BySource`, `ByCategory`

**Sources:** `js-bundle`, `cookies-storage`, `web-storage`, `network-response`, `page-text`, `source-maps`

**Categories:** `jwt-token`, `jwt-sensitive-claim`, `api-key`, `bearer-token`, `password`, `aws-access-key`, `private-key`, `connection-string`, `secret-assignment`, `email-password-combo`, `hardcoded-credential`, `internal-url`, `debug-flag`, `source-map-exposed`, `debug-mode-active`, and more.

```csharp
// Assert no secrets exposed
await AssertSecretsClean();

// Only fail on high/critical
await AssertSecretsClean(minSeverity: "high");

// Full report
var result = await RunSecretsHarvest();
Log($"Sources: {string.Join(", ", result.SourcesScanned)}");
Log($"Findings: {result.TotalFindings} (critical: {result.Summary.Critical}, high: {result.Summary.High})");
foreach (var f in result.Findings)
    Log($"  [{f.Severity}] [{f.Source}] {f.Description} at {f.Location}");

// Scan only JS bundles and storage
var jsOnly = await RunSecretsHarvest(
    includeNetworkResponses: false, includePageText: false, includeSourceMaps: false);

// Printed report with color
await PrintSecretsHarvestReport(includeDetails: true);
```

---

## Client-side firewall test (CSP / SRI / sandbox / Permissions-Policy)

Active verification in the **live** WebView (`FirewallTester`). Optional `tests` collection: `"all"` (default), `csp`, `sri`, `sandbox`, `permissions-policy`.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunFirewallTest` | `IReadOnlyCollection<string>? tests = null, bool verbose = false` | `Task<FirewallResult>` |
| `PrintFirewallTestReport` | `bool includeDetails = true, IReadOnlyCollection<string>? tests = null` | `Task<FirewallResult>` |
| `AssertFirewallTestClean` | `IReadOnlyCollection<string>? tests = null, string? message = null` | `Task` |

**FirewallResult:** `Format(verbose)` — see `Trowser.Security.FirewallResult`.

---

## JWT analysis

Decodes JWT-shaped tokens from `document.cookie`, `localStorage`, `sessionStorage`, and **HttpOnly** cookies (via CookieManager). Optional `explicitTokens` to analyze additional raw strings.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunJwtAnalysis` | `IReadOnlyList<string>? explicitTokens = null` | `Task<JwtAnalyzeResult>` |
| `PrintJwtAnalysisReport` | `bool includePayload = false, IReadOnlyList<string>? explicitTokens = null` | `Task<JwtAnalyzeResult>` |
| `AssertJwtAnalysisClean` | `string? minSeverity = null, IReadOnlyList<string>? explicitTokens = null, string? message = null` | `Task` |

**JwtAnalyzeResult:** `Tokens`, `Format(includePayload)` — `Trowser.Security.HttpSecurityProbes.JwtAnalyzeResult`.

**Severity threshold:** `minSeverity` filters **derived ranks** from algorithm hygiene (`none`=critical, HS256/RS256=medium, expired `exp`=low). **Sensitive claim names** in the payload count as **high** for assertions.

---

## OIDC provider analysis

Fetches `/.well-known/openid-configuration`, analyzes grant types, PKCE, scopes, algorithms, probes endpoints. **Auto-detect** uses the captured network log (discovery URLs, JWT `iss`, `/authorize` links) when `issuer` is omitted.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunOidcAnalysis` | `string? issuer = null, bool autoDetect = true, bool probeEndpoints = true, bool testDynamicRegistration = true, bool testGrantTypes = false, string? clientId = null, int timeoutMs = 20000` | `Task<OidcResult>` |
| `PrintOidcAnalysisReport` | `bool includeDetails = true, ...same as Run...` | `Task<OidcResult>` |
| `AssertOidcAnalysisClean` | `string? minSeverity = null, string? issuer = null, bool testGrantTypes = false, string? message = null` | `Task` |

**OidcResult:** `Trowser.Security.OidcAnalyzer.OidcResult`; formatted text via `OidcAnalyzer.Format(result)`. When **no issuer** can be auto-detected, the assertion **passes (skipped)** — same spirit as SAML-from-network when no SAML is present. If an issuer is known but discovery **fails**, the assertion **fails**.

---

## GraphQL security analysis

Nine checks: introspection, mutations/subscriptions, batching, alias amplification, depth/limit, draft access, field suggestions, rate-limit headers. **Auto-detect** finds a GraphQL HTTP URL from the network log.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunGraphqlAnalysis` | `string? url = null, Dictionary<string, string>? headers = null, bool autoDetect = true, int timeoutMs = 30000`, optional `skip*` flags | `Task<GraphqlResult>` |
| `PrintGraphqlAnalysisReport` | `bool includeDetails = true, string? url = null, ...` | `Task<GraphqlResult>` |
| `AssertGraphqlAnalysisClean` | `string? minSeverity = null, string? url = null, Dictionary<string, string>? headers = null, string? message = null` | `Task` |

**GraphqlResult:** `Trowser.Security.GraphqlAnalyzer.GraphqlResult`; `GraphqlAnalyzer.Format(result)`. No endpoint detected → assertion **passes (skipped)**.

---

## JavaScript static audit (`js-audit`)

Fetches external `script[src]` assets and scans for credential-like assignments, internal URLs, debug markers (`Trowser.Security.JavaScriptStaticAudit`).

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunJavaScriptStaticAudit` | `int maxScripts = 32, int maxBytesPerFile = 524288, bool sameOriginOnly = false, int timeoutMs = 20000` | `Task<JsAuditResult>` |
| `PrintJavaScriptStaticAuditReport` | `bool includeDetails = true, ...same...` | `Task<JsAuditResult>` |
| `AssertJavaScriptStaticAuditClean` | `string? minSeverity = null, string? message = null` | `Task` |

**Hit severity (assertions):** credential-like / email-credential-proximity → high; internal URL → medium; debug-or-test → low.

---

## HTTP request smuggling (raw TCP)

Timing probes plus PortSwigger-style differential-response confirmation (`HttpRequestSmugglingScanner`) against the **document URL** origin. Optional `techniques`, `timeoutMs`, `delayThresholdMs`, `teObfuscations`.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunHttpSmugglingScan` | `string? url = null, IReadOnlyList<string>? techniques = null, int timeoutMs = 10000, int delayThresholdMs = 3000, bool teObfuscations = true` | `Task<SmugglingResult>` |
| `PrintHttpSmugglingReport` | same optional params | `Task<SmugglingResult>` |
| `AssertHttpSmugglingClean` | `string? minSeverity = null, string? url = null, string? message = null` | `Task` |

**SmugglingResult:** `Format()` — `Trowser.Security.HttpRequestSmugglingScanner.SmugglingResult`.

---

## WAF bypass probe

Tests which classic WAF bypass techniques reach the backend when a canonical attack payload is blocked. Sends benign baseline → direct probe → bypass transforms (URL encoding, comments, case, XFF spoof, HPP, etc.). Vendor fingerprinting is out of scope — use `CheckTechStack()` or external tools.

**Requires active probes** — blocked in `--safe` mode (same gate as `POST /api/security/waf-bypass`).

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunWafBypassScan` | `string? url = null, string? paramName = null, string method = "GET", string category = "sqli", string? probePayload = null, string baselineValue = "1", IReadOnlyList<string>? techniques = null, int timeoutMs = 15000, bool useBackendFetch = false, bool includeBrowserCookies = true, string? body = null, Dictionary<string, string>? headers = null` | `Task<WafBypassResult>` |
| `RunWafBypassScan` | `WafBypassOptions options` | `Task<WafBypassResult>` |
| `PrintWafBypassReport` | Same optional params as simple `RunWafBypassScan`, plus `bool includeDetails = true` | `Task<WafBypassResult>` |
| `AssertWafBypassEffective` | `string? url = null, string? paramName = null, string category = "sqli", string? probePayload = null, IReadOnlyList<string>? techniques = null, int timeoutMs = 15000, string? message = null` | `Task` |

**Injection point:** `url` with `§PAYLOAD§` / `{{PAYLOAD}}` marker, or plain `url` + `paramName` (adds/replaces query param). Omit `url` for current page.

**Categories:** `sqli` (default), `xss`, `lfi`, `custom` — selects default `probePayload` when omitted.

**WafBypassResult:** `WafBlockDetected`, `WafIndicators`, `UsableBypasses`, `Techniques[]` (`Technique`, `Verdict`: `blocked`/`bypassed`/`inconclusive`), `Format(includeDetails?)`.

```csharp
// Query param on current page (or discovered URL)
var result = await RunWafBypassScan(paramName: "id", category: "sqli");
await PrintWafBypassReport(url: "https://app.example/search?q=test", paramName: "q", category: "xss");

// Defender regression: WAF blocked probe and no bypass worked
await AssertWafBypassEffective(paramName: "id");

// Fuzz-style template (POST JSON body)
await RunWafBypassScan(
    url: "https://app.example/api/items",
    method: "POST",
    body: "{\"name\":\"§PAYLOAD§\"}",
    category: "sqli");
```

---

## Injection scanners (SQLi, XSS, SSTI, SSRF)

Active probes that match `POST /api/security/{sqli,xss,ssti,ssrf}-scan`. Prefer playbook `a05-injection` / `a11-ssrf` for breadth; use these for focused proof.

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunSqliScan` | `urlTemplate, method = "GET", headers?, bodyTemplate?, baselineValue = "1", payloads?, includeTimeBased = false, timeoutMs = 15000, useBackendFetch = false, includeBrowserCookies = false, includeOrmClosurePayloads = false, depth = null, ct` | `Task<HttpSecurityProbes.SqliScanResult>` |
| `RunXssScan` | `XssScanRunner.XssScanOptions` (`Url`/`ParamName` or `RequestUrlTemplate`, `Depth`, `IncludeReflected`/`IncludeDom`/`IncludeStored`, …) | `Task<XssScanBatchResult>` |
| `RunSstiScan` | `SstiScanRunner.SstiScanOptions` (`UrlTemplate`+markers or discover from network; `Depth`) | `Task<SstiScanBatchResult>` |
| `RunSsrfScan` | `SsrfOptions` | `Task<SsrfResult>` |

**Depth:** `quick` \| `standard` \| `deep` (same semantics as REST).

**SqliScanResult / XssScanBatchResult / SstiScanBatchResult:** `Findings` is `List<UnifiedSecurityFinding>`; use `ToSecurityScanResult()` for the shared envelope (`Message`, `Depth`, `HasFindings`, `Summary`, `Details`).

```csharp
await Navigate("https://target.example/search?q=test");

// SQLi — marker in query
var sqli = await RunSqliScan(
    "https://target.example/search?q=§q§",
    depth: "standard");
foreach (var f in sqli.Findings)
    Log($"[{f.Severity}/{f.Confidence}] {f.Title}: {f.Param} — {f.ProofHint}");

// XSS — discover params or pass explicit
var xss = await RunXssScan(new XssScanRunner.XssScanOptions
{
    ParamName = "q",
    Depth = "standard",
    IncludeReflected = true,
    IncludeDom = true
});
Log(xss.Format());

// SSTI — explicit template
var ssti = await RunSstiScan(new SstiScanRunner.SstiScanOptions
{
    UrlTemplate = "https://target.example/render?template=§INJECT§",
    ParamName = "template",
    Depth = "deep"
});

// SSRF
var ssrf = await RunSsrfScan(new SsrfOptions
{
    MaxCandidates = 8,
    MinConfidence = "likely"
});
```

---

## CSTI scan (client-side template injection)

Probes **client-side** template engines (AngularJS, Vue, Handlebars) by navigating with `{{7*7}}` in URL query/hash parameters and checking the **rendered DOM** for arithmetic evaluation (`49`). Unlike `browser_security_ssti_scan` / server-side SSTI, this uses real browser navigation — required when templates compile in the client.

**Requires active probes** — blocked in `--safe` mode (same gate as `POST /api/security/csti-scan`).

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunCstiScan` | `string? url = null, string? paramName = null, IReadOnlyList<string>? engines = null, IReadOnlyList<string>? sources = null, bool escalate = false, bool monitorSinks = true, int maxCandidates = 10, int timeoutMs = 10000` | `Task<CstiScanBatchResult>` |
| `RunCstiScan` | `CstiScanRunner.CstiScanOptions options` | `Task<CstiScanBatchResult>` |
| `PrintCstiScanReport` | Same optional params as simple `RunCstiScan`, plus `bool includeDetails = true` | `Task<CstiScanBatchResult>` |
| `AssertCstiScanClean` | `string minSeverity = "medium", string? url = null, string? paramName = null, IReadOnlyList<string>? engines = null, IReadOnlyList<string>? sources = null, bool escalate = false, bool monitorSinks = true, int maxCandidates = 10, int timeoutMs = 10000, string? message = null` | `Task` |

**Discovery:** current URL query params, same-origin GET params from network log, inline-script param names (`location.hash` / `location.search`). **Engines:** auto-prioritized from `CheckTechStack()` when `engines` omitted.

**CstiScanBatchResult:** `HasFindings`, `Findings[]` (Parameter, Source, Engine, BasicExpression, EvaluatedToken, CodeExecution, Sinks, Severity), `Format(includeDetails?)`.

```csharp
// Quicktest-style: browse first, then scan
var stack = await CheckTechStack();
var result = await PrintCstiScanReport(monitorSinks: true, escalate: false);
await AssertCstiScanClean(minSeverity: "medium");

// Explicit parameter on current page
await RunCstiScan(paramName: "search", sources: new[] { "url-query" }, engines: new[] { "angularjs" });
```

---

## HTML Validation (html-validate)

Validates the current page's HTML markup for errors, accessibility issues, deprecated elements, and content model violations.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertHtmlValid` | `string? message = null` | `Task` |
| `CheckHtml` | (none) | `Task<HtmlValidateResult>` |
| `PrintHtmlReport` | `bool includeDetails = true` | `Task<HtmlValidateResult>` |

**HtmlValidateResult:** `Url`, `Messages`, `ErrorCount`, `WarningCount`, `TotalCount`, `IsValid`, `GetErrors()`, `GetByCategory(category)`, `GetByRule(ruleId)`, `Format(includeDetails?)`

**HtmlValidateMessage:** `RuleId`, `Severity`, `Message`, `Line`, `Column`, `Offset`, `Size`, `RuleUrl`, `Category`

**HtmlSeverity:** `HtmlSeverity.Warning` (1), `HtmlSeverity.Error` (2)

**Categories:** Accessibility, Content Model, HTML Syntax, Document, Deprecated, Security, Style

**Rule preset:** Uses `html-validate:recommended` with style-only rules disabled (trailing whitespace, inline style, attribute quotes, etc.) to focus on functional issues and avoid false positives.

```csharp
await AssertHtmlValid();
await AssertHtmlValid(message: "Homepage markup is valid");

var result = await CheckHtml();
foreach (var msg in result.GetErrors())
    Log($"line {msg.Line}: {msg.Message} ({msg.RuleId})");

// Check accessibility-related HTML issues specifically
var a11y = result.GetByCategory("Accessibility");
Assert.Equal(0, a11y.Count, "No accessibility issues in HTML");
```

---

## Link Checking

Checks all links on the page for broken URLs, redirects, and errors. Sends HEAD requests (falls back to GET on 405) from the server side to avoid CORS restrictions. Redirects are observations, not errors.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertLinksValid` | `string scope = "anchors", bool external = true, int timeoutMs = 5000, int concurrency = 10, int delayMs = 100, string? message = null` | `Task` |
| `CheckLinks` | `string scope = "anchors", bool external = true, int timeoutMs = 5000, int concurrency = 10, int delayMs = 100` | `Task<LinkCheckResult>` |
| `PrintLinkCheckReport` | `string scope = "anchors", bool external = true, int timeoutMs = 5000, int concurrency = 10, int delayMs = 100, bool includeDetails = true` | `Task<LinkCheckResult>` |

**LinkCheckResult:** `Url`, `TotalLinks`, `CheckedCount`, `BrokenCount`, `RedirectCount`, `SkippedCount`, `Links`, `Broken`, `IsClean`, `Format(includeDetails?)`

**CheckedLink:** `Url`, `OriginalUrl`, `Source`, `Status`, `StatusCode`, `RedirectUrl`, `Error`, `LinkText`

**LinkStatus enum:** `LinkStatus.Ok` (2xx), `LinkStatus.Redirect` (3xx), `LinkStatus.Broken` (4xx/5xx), `LinkStatus.Timeout`, `LinkStatus.Error`, `LinkStatus.Skipped`

**Scope:** `"anchors"` = `<a>` tags only (default), `"resources"` = images, scripts, stylesheets, iframes, `"all"` = everything.

```csharp
// Basic: check all anchor links
await AssertLinksValid();

// Check all resources (images, scripts, stylesheets too)
await AssertLinksValid(scope: "all");

// Only internal links, with custom timeout
await AssertLinksValid(external: false, timeoutMs: 10000);

// Slow down to avoid 429 rate limiting on busy sites
await AssertLinksValid(delayMs: 200);

var result = await CheckLinks();
Log($"Checked {result.CheckedCount} links, {result.BrokenCount} broken");

foreach (var link in result.Broken)
    Log($"  [{link.StatusCode}] {link.Url}");

// Redirects are observations -- check them separately if needed
foreach (var link in result.Links.Where(l => l.Status == LinkStatus.Redirect))
    Log($"  Redirect: {link.Url} → {link.RedirectUrl}");

await PrintLinkCheckReport(scope: "anchors", includeDetails: true);
```

---

## DOM XSS Audit

Audits the page's DOM for XSS-prone patterns. Inspired by OWASP ZAP passive scan rules. Checks inline event handlers, `javascript:` URLs, dangerous sinks, cross-domain scripts without SRI, data URIs, external form actions, and base tag hijacking.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertXssClean` | `XssSeverity? minSeverity = null, string? message = null` | `Task` |
| `CheckXss` | (none) | `Task<XssResult>` |
| `PrintXssReport` | `bool includeDetails = true` | `Task<XssResult>` |

**XssResult:** `Url`, `Findings`, `FindingCount`, `FindingsByCategory`, `IsClean`, `GetByMinSeverity(severity)`, `Format(includeDetails?)`

**XssFinding:** `Category`, `Severity`, `Description`, `Location`, `Evidence`, `Recommendation`

**XssSeverity enum:** `XssSeverity.Info`, `XssSeverity.Low`, `XssSeverity.Medium`, `XssSeverity.High`

**Finding categories:** `inline-handler`, `javascript-url`, `data-uri-execution`, `cross-domain-script`, `cross-domain-script-summary`, `inline-script`, `dangerous-sink`, `external-form-action`, `base-tag-hijack`

```csharp
// Basic: assert no medium+ XSS risks
await AssertXssClean(minSeverity: XssSeverity.Medium);

// Check everything including info-level findings
await AssertXssClean();

var result = await CheckXss();
Log($"Found {result.FindingCount} XSS-related findings");

foreach (var cat in result.FindingsByCategory)
    Log($"  {cat.Key}: {cat.Value}");

// Only high-severity findings
var high = result.GetByMinSeverity(XssSeverity.High);
Assert.Equal(0, high.Count, "No high-severity XSS patterns");

await PrintXssReport(includeDetails: true);
```

---

## Backward Compatibility

Analyzes the page's JavaScript for backward compatibility with older browsers. Downloads and scans all scripts (inline and external) for modern ES2020+ syntax features and newer Web APIs.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertCompatible` | `int? minIos = null, int? minAndroid = null, string? message = null` | `Task` |
| `CheckCompatibility` | `int? minIos = null, int? minAndroid = null` | `Task<CompatibilityResult>` |
| `PrintCompatibilityReport` | `bool includeDetails = true, int? minIos = null, int? minAndroid = null` | `Task<CompatibilityResult>` |

**CompatibilityResult:** `Url`, `IsCompatible`, `ScriptsAnalyzed`, `TotalBytesAnalyzed`, `SkippedScripts`, `Features`, `Targets`, `Format(includeDetails?)`

**DetectedFeature:** `Name`, `Category`, `ChromeMin`, `SafariMin`, `FirefoxMin`, `Occurrences`, `FoundIn`, `MdnUrl`, `IncompatibleWith`

**FeatureCategory enum:** `FeatureCategory.Syntax` (causes parse errors — critical), `FeatureCategory.Api` (runtime errors — moderate)

```csharp
// Basic: assert compatible with iOS 15 and Android 10 (defaults)
await AssertCompatible();

// Custom targets
await AssertCompatible(minIos: 16, minAndroid: 12);

var result = await CheckCompatibility();
Log($"Analyzed {result.ScriptsAnalyzed} scripts, {result.Features.Count} modern features found");

foreach (var f in result.Features)
    Log($"  {f.Name} ({f.Category}) — {f.Occurrences} occurrence(s)");

await PrintCompatibilityReport(includeDetails: true);
```

---

## Structured Text Extraction

Extracts all visible text from the page in a structured format, designed for proofreading and text analysis workflows. Returns headings (with hierarchy), paragraphs, link texts, button labels, form labels, image alt texts, and more.

| Method | Parameters | Returns |
|--------|------------|---------|
| `GetStructuredText` | (none) | `Task<StructuredTextResult>` |
| `PrintStructuredText` | (none) | `Task<StructuredTextResult>` |

**StructuredTextResult:** `Url`, `Title`, `Language`, `MetaDescription`, `Headings`, `Paragraphs`, `Links`, `Buttons`, `Labels`, `Images`, `WordCount`, `AllText`, `Format()`

**PageHeading:** `Level` (1-6), `Text`

**PageLink:** `Text`, `Url`

**PageImage:** `Alt`, `Src`

```csharp
var text = await GetStructuredText();
Log($"Page has {text.WordCount} words, {text.Headings.Count} headings, {text.Links.Count} links");

// Check heading hierarchy
foreach (var h in text.Headings)
    Log($"  {"".PadLeft(h.Level * 2)}H{h.Level}: {h.Text}");

// Find images without alt text
var missingAlt = text.Images.Where(i => string.IsNullOrWhiteSpace(i.Alt)).ToList();
Assert.Equal(0, missingAlt.Count, "All images should have alt text");

// Get full text for spell-checking or analysis
Log(text.AllText);

await PrintStructuredText();
```

---

## GUI Consistency & Image Optimization

Audits the page's visual consistency by analyzing computed styles, and checks images for optimization issues. Checks font families, font sizes, text colors, background colors, button heights, input heights, spacing values, and image best practices. Warns when counts exceed thresholds indicating design inconsistency.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertConsistent` | `string? message = null` | `Task` |
| `CheckConsistency` | (none) | `Task<ConsistencyResult>` |
| `PrintConsistencyReport` | `bool includeDetails = true` | `Task<ConsistencyResult>` |

**ConsistencyResult:** `Url`, `Stats`, `Findings`, `IsClean`, `WarningCount`, `Format(includeDetails?)`

**ConsistencyStats:** `FontFamilies`, `FontSizes`, `TextColors`, `BackgroundColors`, `ButtonHeights`, `InputHeights`, `SpacingValues` (each is `List<ValueCount>`), `ImageIssues` (`List<ImageIssue>`)

**ValueCount:** `Value`, `Count`

**ImageIssue:** `Src`, `IssueType` ("oversized", "missing-dimensions", "missing-lazy"), `Description`, `NaturalWidth`, `NaturalHeight`, `DisplayedWidth`, `DisplayedHeight`

**ConsistencyFinding:** `Category`, `Description`, `IsWarning`, `Values`

**Warning thresholds:** Font families > 4, font sizes > 8, text colors > 10, background colors > 8, button heights > 3, input heights > 3, spacing values > 12.

**Image checks:** Oversized images (natural > 2x displayed), missing `width`/`height` attributes (causes CLS), missing `loading="lazy"` on below-fold images.

```csharp
// Basic: assert visual consistency (includes image checks)
await AssertConsistent();

var result = await CheckConsistency();
Log($"Font families: {result.Stats.FontFamilies.Count}");
Log($"Text colors: {result.Stats.TextColors.Count}");
Log($"Image issues: {result.Stats.ImageIssues.Count}");

// Check image optimization specifically
foreach (var img in result.Stats.ImageIssues)
    Log($"  [{img.IssueType}] {img.Description}");

await PrintConsistencyReport(includeDetails: true);
```

---

## Tech Stack Detection

Fingerprints the target's technology stack by analyzing HTTP response headers, cookies, DOM patterns (meta tags, data attributes, global JS objects), and script URLs. Detects web servers, frameworks, languages, JavaScript libraries/frameworks, WAFs, CDNs, CMSes, and analytics. Useful for reconnaissance — knowing the stack guides which fuzz payloads, CVE databases, and attack vectors to prioritize.

| Method | Parameters | Returns |
|--------|------------|---------|
| `CheckTechStack` | (none) | `Task<TechStackResult>` |
| `PrintTechStackReport` | `bool includeDetails = true` | `Task<TechStackResult>` |
| `AssertNoWaf` | `string? message = null` | `Task` |

**TechStackResult:** `Url`, `Timestamp`, `ElapsedMs`, `Detections`, `DetectionCount`, `Categories`, `Frameworks`, `Servers`, `JsLibraries`, `Waf`, `Cdn`, `GetByCategory(category)`, `Format(includeDetails?)`

**TechStackDetection:** `Name`, `Version`, `Category`, `Evidence`, `Source`, `Confidence`

**Categories:** `server`, `language`, `framework`, `js-library`, `js-framework`, `cms`, `cdn`, `waf`, `analytics`

**Sources:** `response-header`, `cookie`, `meta-tag`, `script-src`, `js-global`, `dom`, `stylesheet`

```csharp
// Print full tech stack report
await PrintTechStackReport();

// Programmatic access
var result = await CheckTechStack();
Log($"Detected {result.DetectionCount} technologies");

foreach (var d in result.Detections)
    Log($"  [{d.Category}] {d.Name} {d.Version ?? ""} (confidence: {d.Confidence:F1}, source: {d.Source})");

// Check for WAFs that may filter fuzz payloads
if (result.Waf.Count > 0)
    Log($"WARNING: WAF detected: {string.Join(", ", result.Waf.Select(w => w.Name))}");

// Assert no WAF (useful before fuzzing)
await AssertNoWaf();

// Get specific categories
var frameworks = result.Frameworks;
var jsLibs = result.JsLibraries;
```

---

## Third-Party Resource Inventory

Inventories all third-party resources loaded by the page — external scripts, stylesheets, iframes, and fonts. Shows domains, transfer sizes, and Subresource Integrity (SRI) coverage. Useful for privacy audits, GDPR compliance, and supply chain security.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertThirdPartySecure` | `string? message = null` | `Task` |
| `CheckThirdParty` | (none) | `Task<ThirdPartyResult>` |
| `PrintThirdPartyReport` | `bool includeDetails = true` | `Task<ThirdPartyResult>` |

**ThirdPartyResult:** `Url`, `Resources`, `TotalCount`, `Domains`, `DomainCount`, `TotalSizeBytes`, `SriCount`, `IsClean`, `Format(includeDetails?)`

**ThirdPartyResource:** `Url`, `Domain`, `Type` ("script"/"stylesheet"/"iframe"/"font"/"other"), `SizeBytes`, `HasSri`, `IntegrityHash`

```csharp
await AssertThirdPartySecure();

var result = await CheckThirdParty();
Log($"Third-party: {result.TotalCount} resources from {result.DomainCount} domains");
Log($"SRI coverage: {result.SriCount} / {result.TotalCount}");

foreach (var r in result.Resources.Where(r => !r.HasSri && r.Type == "script"))
    Log($"  Script without SRI: {r.Url}");

await PrintThirdPartyReport(includeDetails: true);
```

---

## Mixed Content Detection

Checks for HTTP resources loaded on HTTPS pages. Active mixed content (scripts, iframes) is blocked by modern browsers. Passive mixed content (images, stylesheets) may be degraded. Returns clean result on HTTP pages (not applicable).

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertNoMixedContent` | `MixedContentSeverity? minSeverity = null, string? message = null` | `Task` |
| `CheckMixedContent` | (none) | `Task<MixedContentResult>` |
| `PrintMixedContentReport` | `bool includeDetails = true` | `Task<MixedContentResult>` |

**MixedContentResult:** `Url`, `IsHttps`, `Findings`, `FindingCount`, `IsClean`, `HighCount`, `MediumCount`, `LowCount`, `Format(includeDetails?)`

**MixedContentFinding:** `Tag`, `Attribute`, `Url`, `Severity`, `Context`

**MixedContentSeverity enum:** `MixedContentSeverity.High` (scripts, iframes — active), `MixedContentSeverity.Medium` (images, styles — passive), `MixedContentSeverity.Low` (other)

```csharp
await AssertNoMixedContent();

// Only fail on active mixed content (scripts/iframes)
await AssertNoMixedContent(minSeverity: MixedContentSeverity.High);

var result = await CheckMixedContent();
if (result.IsHttps)
    Log($"Mixed content: {result.FindingCount} issues ({result.HighCount} high, {result.MediumCount} medium)");

await PrintMixedContentReport(includeDetails: true);
```

---

## Source Map & Debug Mode Audit

Detects source map references (`sourceMappingURL` directives), accessible `.map` files, and framework debug mode indicators (Angular, React, Vue, Redux) that should not be exposed in production.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertNoSourceMaps` | `Severity? minSeverity = null, string? message = null` | `Task` |
| `CheckSourceMaps` | (none) | `Task<SourceMapResult>` |
| `PrintSourceMapReport` | `bool includeDetails = true` | `Task<SourceMapResult>` |

**SourceMapResult:** `Url`, `Timestamp`, `Findings`, `FindingCount`, `IsClean`, `Format(includeDetails?)`

**SourceMapFinding:** `Severity` (`Severity` enum: High, Medium, Low), `Category` (string: `AccessibleMapFile`, `SourceMapReference`, `DebugMode`), `Description`, `Url`, `Detail`

```csharp
await AssertNoSourceMaps();

// Only fail on accessible .map files (high severity)
await AssertNoSourceMaps(minSeverity: Severity.High);

var result = await CheckSourceMaps();
Log($"Source map findings: {result.FindingCount}");

await PrintSourceMapReport(includeDetails: true);
```

---

## Cookie Security (OWASP)

Audits all cookies against OWASP best practices: Secure flag, HttpOnly on session cookies, SameSite configuration, domain scoping, and cookie lifetime. Included in `POST /api/audit-all` as `cookieSecurity`.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertCookieSecurity` | `Severity? minSeverity = null, string? message = null` | `Task` |
| `CheckCookieSecurity` | (none) | `Task<CookieAuditResult>` |
| `PrintCookieSecurityReport` | `bool includeDetails = true` | `Task<CookieAuditResult>` |

**CookieAuditResult:** `Url`, `Timestamp`, `CookieCount`, `Findings`, `Checklist`, `FindingCount`, `IsClean`, `Format(includeDetails?)`

**CookieFinding:** `CookieName`, `Severity` (`Severity` enum), `Category` (string: `MissingSecure`, `MissingHttpOnly`, `SameSiteNone`, `SameSiteNoneInsecure`, `BroadDomain`, `ExcessiveLifetime`), `Description`, `Recommendation`

**CookieChecklistItem:** `Pass` (bool), `Issue` (string or null), `Cookies` (list of cookie names)

**Checklist keys:** `"Secure flag on HTTPS"`, `"HttpOnly on session cookies"`, `"SameSite configured"`, `"No overly broad domain"`, `"Session cookie lifetime"`

```csharp
// Assert no cookie issues (medium+ severity)
await AssertCookieSecurity(minSeverity: Severity.Medium);

// Full report
await PrintCookieSecurityReport();

// Programmatic access
var result = await CheckCookieSecurity();
Log($"Cookie issues: {result.FindingCount}");
foreach (var check in result.Checklist)
    Log($"  [{(check.Value.Pass ? "PASS" : "FAIL")}] {check.Key}");
```

---

## Web Storage Security Audit

Scans `localStorage` and `sessionStorage` for risky content (auth tokens in localStorage, PII, stored XSS-like payloads, secrets). Same analysis as `POST /api/security/storage` and the `storageSecurity` section of `POST /api/audit-all`.

| Method | Parameters | Returns |
|--------|------------|---------|
| `CheckStorageSecurity` | (none) | `Task<StorageAuditResult>` |
| `PrintStorageSecurityReport` | `bool includeDetails = true` | `Task<StorageAuditResult>` |
| `AssertStorageSecurity` | `Severity? minSeverity = null, string? message = null` | `Task` |

**StorageAuditResult:** `Url`, `Timestamp`, `LocalStorageCount`, `SessionStorageCount`, `Findings`, `FindingCount`, `IsClean`, `Format(includeDetails?)`

**StorageFinding:** `StorageType`, `Key`, `Severity`, `Category`, `Description`, `Recommendation`, `ValueSnippet`

```csharp
await AssertStorageSecurity(minSeverity: Severity.Medium);
await PrintStorageSecurityReport();
```

---

## Robustness (gremlins.js)

Runs monkey testing by unleashing random user actions (clicks, typing, form filling, scrolling, touch) to test page robustness.

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertRobust` | `MonkeyTestOptions? options = null, string? message = null` | `Task` |
| `RunMonkeyTest` | `MonkeyTestOptions? options = null` | `Task<MonkeyTestResult>` |
| `RunMonkeyTest` | `int actions = 500, int delay = 20, int? seed = null` | `Task<MonkeyTestResult>` |
| `PrintMonkeyTestReport` | `MonkeyTestOptions? options = null` | `Task<MonkeyTestResult>` |

**MonkeyTestOptions:** `Actions` (default 500), `Delay` (ms, default 20), `Seed` (null = random), `Species` (flags: `Clicker`, `Toucher`, `FormFiller`, `Scroller`, `Typer`, `All`), `MaxErrors` (default 50)

**MonkeyTestResult:** `StartUrl`, `EndUrl`, `Navigated`, `DurationSeconds`, `ActionsPerformed`, `Seed`, `Errors`, `ErrorCount`, `NavigationAttempts`, `FpsDrops`, `LowestFps`, `StoppedEarly`, `Survived`, `UniqueErrors`, `Format(includeDetails?)`

**MonkeyTestError:** `Type` ("error", "unhandledrejection", "gremlin"), `Message`, `Source`, `Line`

**NavigationAttempt:** `Type` ("link", "form", "window.open", "location", "navigation"), `Url`

**Navigation blocking:** During the test, all navigations are blocked (link clicks, form submissions, `window.open`, `location.assign/replace`). Attempted navigations are recorded in `NavigationAttempts` instead. This keeps the test running and also reports which actions would have caused the user to leave the page.

**MonkeySpecies (flags enum):** `MonkeySpecies.Clicker`, `MonkeySpecies.Toucher`, `MonkeySpecies.FormFiller`, `MonkeySpecies.Scroller`, `MonkeySpecies.Typer`, `MonkeySpecies.All`

```csharp
// Quick test with defaults (500 actions, ~10s)
await AssertRobust();

// Longer stress test
await AssertRobust(new MonkeyTestOptions { Actions = 2000, Delay = 10 });

// Short targeted test with reproducible seed
var result = await RunMonkeyTest(actions: 200, seed: 42);
Log($"Survived: {result.Survived}, Errors: {result.ErrorCount}, Seed: {result.Seed}");

// Only click and type (no form filling/scrolling)
await RunMonkeyTest(new MonkeyTestOptions
{
    Species = MonkeySpecies.Clicker | MonkeySpecies.Typer,
    Actions = 300
});

// Reproduce a failure
await RunMonkeyTest(seed: 54321);
```

---

## Monkey Trowser (Smart Robustness)

Intelligent robustness tester that systematically clicks every interactive element, fuzzes forms with edge-case data, and crawls within navigation scope. Requires scope to be set (not `*.*`).

### Top-Level Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `AssertSmartMonkey` | `int maxActions = 100, bool followLinks = true, int maxPages = 10` | `Task` |
| `RunSmartMonkey` | `int maxActions = 100, bool followLinks = true, int maxPages = 10` | `Task<SmartTestResult>` |
| `PrintSmartMonkeyReport` | `SmartTestOptions? options = null` | `Task<SmartTestResult>` |
| `PrintSmartMonkeyReport` | `SmartTestResult result` | `void` |
| `AssertSmartMonkey` | `SmartTestResult result, string? message = null` | `void` |

**SmartTestOptions:** `FollowLinks` (default true), `FuzzForms` (default true), `MaxPages` (default 10), `MaxActionsPerPage` (default 100)

**SmartTestResult:** `Passed`, `IssueCount`, `PagesVisited`, `ElementsTested`, `FormsFuzzed`, `DurationSeconds`, `Issues` (list of `SmartTestIssue`), `PageSummaries`

**SmartTestIssue:** `Page`, `Element`, `Action`, `Issue`, `IssueType` (one of: `js-error`, `network-error`, `dead-link`, `page-error`)

### Examples

```csharp
// Quick smart test with defaults (100 actions/page, follow links, max 10 pages)
await AssertSmartMonkey();

// Only test current page (no crawling)
await AssertSmartMonkey(followLinks: false);

// More actions, crawl up to 20 pages
var result = await RunSmartMonkey(maxActions: 200, maxPages: 20);
Log($"Passed: {result.Passed}, Pages: {result.PagesVisited}, Issues: {result.IssueCount}");

// Run once, then report and assert on the same result
var r = await RunSmartMonkey(maxActions: 50);
PrintSmartMonkeyReport(r);
AssertSmartMonkey(r);
```

---

## TrowserInterrupter (Fault Injection)

Auto-discovers API endpoints from the network log, ranks them by relevance (JSON content type, API-like paths, same-origin, HTTP method), injects faults via mocks, reloads the page, replays user actions, and checks for failures. Same-origin filtering by default.

### Top-Level Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `RunInterrupterTest` | `InterrupterOptions? options = null` | `Task<InterrupterResult>` |

**InterrupterOptions:**

| Property | Default | Description |
|----------|---------|-------------|
| `Url` | `null` | Target a specific URL (bypasses auto-discovery — works even if not in network log) |
| `Method` | `null` | Filter by HTTP method |
| `Faults` | `null` | Subset of built-in fault preset names. `null` = default 5 |
| `MaxEndpoints` | `5` | Max auto-discovered endpoints (ranked by relevance score) |
| `WaitForIdle` | `false` | Wait for network idle before endpoint discovery |
| `AllowedHosts` | `null` | Additional hosts to include in discovery beyond current page's origin |
| `CooldownMs` | `0` | Delay in ms between scenarios to avoid rate limits |
| `CustomFaults` | `null` | List of `CustomFault` objects: `{Name, Status, Body?, Headers?, DelayMs}` |
| `Actions` | `null` | List of `InterrupterAction` objects to replay after each reload |

**InterrupterAction:** `Action` (click/type/select/hover/press_key/scroll/wait), `Selector`, `ByText`, `Placeholder`, `Role`, `Name`, `Label`, `TestId`, `Text`, `Value`, `Key`, `DelayMs`, `Ref`

**InterrupterResult:** `StartUrl`, `Timestamp`, `DurationSeconds`, `EndpointsTested`, `ScenarioCount`, `Passed`, `Failed`, `DiscoveredEndpoints`, `Scenarios`, `Options`, `Format(includeDetails?)`

**InterrupterScenario:** `Endpoint`, `Method`, `FaultName`, `FaultDescription`, `Passed`, `Signals`

**InterrupterSignal:** `Type`, `Message`, `Source`

**DiscoveredEndpoint:** `UrlPattern`, `Method`, `OriginalUrl`, `ResponseBody`, `ContentType`, `ResourceType`, `RelevanceScore`

**Default fault presets:** `server-error` (500), `not-found` (404), `empty-body` (200 empty), `invalid-json` (200 malformed), `slow-response` (200 + 10s delay)

**Extra fault presets** (request by name): `unauthorized` (401), `forbidden` (403), `rate-limited` (429 + Retry-After), `mutate-response` (corrupted version of the original response)

**Evaluation signals:** `console-error`, `uncaught-exception`, `blank-page`, `network-error`, `content-changed` (Jaccard similarity < 50%), `error-page` (URL/title matches error patterns)

### Examples

```csharp
// Basic: auto-discover endpoints, test with default 5 faults
var result = await RunInterrupterTest(new InterrupterOptions { });
Log(result.Format());

// Target a specific endpoint not in the network log
var result = await RunInterrupterTest(new InterrupterOptions
{
    Url = "/api/checkout",
    Method = "POST",
    Faults = new List<string> { "server-error", "unauthorized", "forbidden" }
});

// Wait for idle before discovery (after fresh navigation)
await Navigate("https://example.com/app");
var result = await RunInterrupterTest(new InterrupterOptions { WaitForIdle = true });

// Include a third-party API in discovery
var result = await RunInterrupterTest(new InterrupterOptions
{
    AllowedHosts = new List<string> { "api.partner.com" },
    MaxEndpoints = 10
});

// Cooldown between scenarios to avoid rate limits
var result = await RunInterrupterTest(new InterrupterOptions
{
    CooldownMs = 500,
    Faults = new List<string> { "server-error", "unauthorized", "rate-limited" }
});

// Test with mutate-response (corrupt cached response body)
var result = await RunInterrupterTest(new InterrupterOptions
{
    Url = "/api/users",
    Faults = new List<string> { "mutate-response", "empty-body" }
});

// Custom fault + cooldown
var result = await RunInterrupterTest(new InterrupterOptions
{
    Url = "/api/data",
    CooldownMs = 1000,
    CustomFaults = new List<CustomFault>
    {
        new() { Name = "rate-limited-custom", Status = 429, Body = "{\"error\":\"Too many requests\"}" },
        new() { Name = "gateway-timeout", Status = 504, Body = "" }
    }
});

// Interaction replay: test a user-triggered endpoint (form submission)
var result = await RunInterrupterTest(new InterrupterOptions
{
    Url = "/catalog/subscribe",
    Method = "POST",
    Faults = new List<string> { "server-error", "empty-body" },
    Actions = new List<InterrupterAction>
    {
        new() { Action = "type", Placeholder = "Email address", Text = "test@example.com" },
        new() { Action = "click", ByText = "SUBSCRIBE" }
    }
});
Log($"Passed: {result.Passed}/{result.ScenarioCount}");
```

---

## Request Fuzzer (browser-context)

Intruder-style fuzzing via `fetch()` in the WebView: real cookies, session, and CSRF state. Same engine as `POST /api/fuzz` (see `trowserkit/trowser-api-reference.md` — built-in payload sets, attack types, anomaly flags). **REST calls require** `"safetyMode": "active"`; **C# scripts** call `RunFuzzerTest` directly with no separate gate.

### Top-Level Method

| Method | Returns | Description |
|--------|---------|-------------|
| `RunFuzzerTest(FuzzerOptions options)` | `Task<FuzzerResult>` | Run a fuzz campaign from the script |

| Method | Description |
|--------|-------------|
| `PrintFuzzerReport(FuzzerResult result, bool includeDetails = true)` | Log a colorized report |

### Types (namespace `Trowser.Robustness`)

**FuzzerOptions** — `Request`, `InjectionPoints`, `PayloadSets`, `AttackType` (`Sniper`, `BatteringRam`, `Pitchfork`, `ClusterBomb`), `MaxConcurrency`, `UseBrowserCookies`, `StopOnStatus`, `AcceptableResponseStatuses` (HTTP codes that skip status/length anomaly vs baseline; 5xx, reflection, timing, error-pattern unchanged), `MaxRequests`, `TimeoutMs`, `DelayMs`, `BodySnippetLength`, `MaxResponseBodyLength`, `PayloadGenerators`.

**FuzzerRequestTemplate** — `Url`, `Method`, `Headers`, `Body` (string), optional `Json` (object — serialized to JSON body). Place markers in URL, method, headers, or body as `§NAME§` or `{{NAME}}` (ASCII-safe).

**FuzzerInjectionPoint** — `PayloadSet` (name of a built-in set or a key in `PayloadSets`).

**PayloadSets** — map set name → list of strings, or a single element `"built-in"` to pull the named built-in set (same 17 sets as the REST API: `json-breaking`, `sqli-basic`, `xss-basic`, `ssti`, `path-traversal`, `boundary`, `auth-bypass`, `content-type`, `header-injection`, `unicode-edge`, `java-spring`, `integer-overflow`, `nosql-injection`, `xxe`, `ssrf`, `jwt-manipulation`, `http-method`).

**FuzzerPayloadGenerator** — optional `PayloadGenerators` entries: `Type` (`range`, `pattern`, `combine`), `From`/`To`/`Step`, `Template` (e.g. `user{N}@test.com`), `BaseSet`, `Encodings`.

**FuzzerResult** — `Completed`, `Flagged`, `Results`, `Timing`, `StatusDistribution`, `Format(includeDetails?)`. Each `FuzzRequestResult` includes `InjectedUrl`, `InjectedBody`, `FlagDetails`, `Flagged`.

### Example

```csharp
var result = await RunFuzzerTest(new FuzzerOptions
{
    Request = new FuzzerRequestTemplate
    {
        Url = "https://example.com/api/search?q=§PAYLOAD§",
        Method = "GET",
    },
    InjectionPoints = new Dictionary<string, FuzzerInjectionPoint>
    {
        ["PAYLOAD"] = new FuzzerInjectionPoint { PayloadSet = "sqli-basic" }
    },
    PayloadSets = new Dictionary<string, List<string>>
    {
        ["sqli-basic"] = new List<string> { "built-in" }
    },
    AttackType = FuzzerAttackType.Sniper,
    MaxConcurrency = 4,
    MaxRequests = 40,
    TimeoutMs = 10000,
    AcceptableResponseStatuses = new List<int> { 400, 403, 412, 422 },
});
PrintFuzzerReport(result);
```

The **RequestFuzzer** quicktest auto-discovers candidates from `GetNetworkLog()` (JSON bodies, GET query strings, and request-header tampering on API-like requests for 500-hunting) and runs multiple payload sets. It uses the ASCII-safe `{{PAYLOAD}}` marker (not `§PAYLOAD§`, which `System.Text.Json` escapes to `\u00a7…` inside JSON bodies so it never substitutes) and prints full reproduction details (method, URL, headers, body, and a `curl.exe` line) for every flagged request.

---

## Console Capture

### Top-Level Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `GetConsoleLog()` | `List<ConsoleEntry>` | All messages |
| `GetConsoleErrors()` | `List<ConsoleEntry>` | Errors only |
| `ClearConsoleLog()` | `void` | Clear all |
| `PrintConsoleLog(maxEntries?)` | `void` | Print formatted |

### Console Object Methods

| Method/Property | Description |
|--------|-------------|
| `Console.GetErrors()` | Error entries |
| `Console.GetWarnings()` | Warning entries |
| `Console.Find(text)` | Entries containing text |
| `Console.HasErrors` | bool |

### ConsoleEntry Properties

`Id`, `Level` (Log/Info/Warning/Error), `Message`, `Source`, `Line`, `Timestamp`

---

## Network Logging

### Top-Level Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `GetNetworkLog()` | `List<NetworkEntry>` | All entries |
| `FindRequests(urlSubstring)` | `List<NetworkEntry>` | Match by URL |
| `ClearNetworkLog()` | `void` | Clear all |
| `PrintNetworkLog(maxEntries?)` | `void` | Print formatted |
| `WaitForRequest(urlSubstring, timeoutMs?)` | `Task<NetworkEntry>` | Wait for match. Throws `TimeoutException`. |

### Network Object Methods

| Method | Description |
|--------|-------------|
| `Network.FindByUrl(urlSubstring)` | Match by URL |
| `Network.FindByMethod(method)` | Match by HTTP method |
| `Network.FindByStatus(statusCode)` | Match by status code |
| `Network.FindByType(resourceType)` | Match by type (Document, Script, Stylesheet, Image, XHR, Fetch, etc.) |
| `Network.FindErrors()` | All 4xx and 5xx |

### NetworkEntry Properties

`Id`, `Method`, `Url`, `StatusCode`, `ReasonPhrase`, `ResourceType`, `RequestHeaders`, `ResponseHeaders`, `RequestBody`, `ResponseBody`, `Timestamp`, `DurationMs`, `ContentType`, `Path`, `Host`, `IsError`, `IsSuccess`

- **`DurationMs`** (`double?`): Response time in milliseconds (high-resolution timer, from request start to response received). `null` if timing unavailable. Useful for timing analysis, user enumeration detection, and slow endpoint identification.
- **`ResponseHeaders`**: Includes `Set-Cookie` headers captured via CDP (WebView2 strips them for security). Multiple Set-Cookie values are newline-separated.

---

## Cookie Management

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `GetCookies()` | -- | `Task<List<Dictionary<string, object>>>` | All cookies for the current page URL |
| `GetCookie(name)` | `string name` | `Task<Dictionary<string, object>?>` | A specific cookie by name (null if not found) |
| `SetCookie(name, value, ...)` | `string name, string value, string? domain, string? path, bool? secure, bool? httpOnly, string? sameSite` | `Task` | Set/add a cookie |
| `DeleteCookie(name, ...)` | `string name, string? domain, string? path` | `Task` | Delete a specific cookie |
| `ClearCookies()` | -- | `Task` | Delete all cookies |

**Cookie dictionary fields:** `name`, `value`, `domain`, `path`, `secure` (bool), `httpOnly` (bool), `sameSite` (`"none"`, `"lax"`, `"strict"`), `session` (bool), `expires` (ISO 8601 string or absent for session cookies).

```csharp
// Inspect cookies
var cookies = await GetCookies();
Log($"Total cookies: {cookies.Count}");

var session = await GetCookie("sessionId");
if (session != null)
{
    Assert.True((bool)session["secure"], "Session cookie has Secure flag");
    Assert.True((bool)session["httpOnly"], "Session cookie is HttpOnly");
    Assert.Equal("strict", session["sameSite"]?.ToString(), "Session cookie is SameSite=Strict");
}

// Simulate logged-out state
await DeleteCookie("sessionId");

// Set a test cookie
await SetCookie("testMode", "true", domain: ".example.com", secure: true, sameSite: "Lax");

// Clear all cookies (full logout)
await ClearCookies();
```

---

## Web Storage (localStorage / sessionStorage)

Read and manipulate browser `localStorage` and `sessionStorage`. Many SPAs store auth tokens, user preferences, feature flags, and cached data here.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `GetAllStorage(type)` | `string type` | `Task<Dictionary<string, string>>` | Get all key/value pairs. `type` is `"local"` or `"session"`. |
| `GetStorageItem(type, key)` | `string type, string key` | `Task<string?>` | Get a single value (null if not set). |
| `SetStorageItem(type, key, value)` | `string type, string key, string value` | `Task` | Set a key/value pair. |
| `DeleteStorageItem(type, key)` | `string type, string key` | `Task` | Remove a key. |
| `ClearStorage(type)` | `string type` | `Task` | Clear all entries. |

```csharp
// Read all localStorage
var storage = await GetAllStorage("local");
Log($"localStorage has {storage.Count} entries");
foreach (var (key, value) in storage)
    Log($"  {key} = {value}");

// Check a specific key
var theme = await GetStorageItem("local", "theme");
Assert.Equal("dark", theme, "User prefers dark mode");

// Simulate fresh-user experience
await ClearStorage("local");
await Navigate(await GetCurrentUrl());
await WaitForIdle();

// Test feature flags
await SetStorageItem("local", "featureFlags", "{\"newUI\":true,\"betaMode\":false}");
await Navigate(await GetCurrentUrl());
await WaitForIdle();
await AssertElementVisible(".new-dashboard");

// Test expired auth token
await DeleteStorageItem("local", "authToken");
await Navigate("/dashboard");
await AssertPageContains("Please sign in");

// sessionStorage works the same way
var sessionData = await GetAllStorage("session");
await SetStorageItem("session", "tempData", "test");
```

---

## Network Throttling

Simulate degraded network conditions to test loading spinners, timeouts, and perceived performance on slow connections.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `SetNetworkThrottle(preset)` | `string preset` | `Task` | Enable throttling with a preset: `2G`, `Slow3G`, `3G`, `4G`, `Offline`. |
| `SetNetworkThrottle(downloadKbps, uploadKbps, latencyMs, offline?)` | `double, double, int, bool = false` | `Task` | Enable throttling with custom values. |
| `ClearNetworkThrottle()` | -- | `Task` | Disable throttling and restore full speed. |

**Presets:**

| Preset | Download | Upload | Latency |
|--------|----------|--------|---------|
| `Offline` | 0 | 0 | 0 (offline) |
| `2G` | 32 KB/s | 6.4 KB/s | 1800ms |
| `Slow3G` | 50 KB/s | 20 KB/s | 2000ms |
| `3G` | 188 KB/s | 38 KB/s | 562ms |
| `4G` | 1500 KB/s | 750 KB/s | 170ms |

```csharp
// Test loading experience on 3G
await SetNetworkThrottle("3G");
await Navigate("https://example.com");
await WaitForIdle();
await AssertElementVisible(".loading-spinner");

// Measure Web Vitals under slow network
await SetNetworkThrottle("Slow3G");
await Navigate("https://example.com");
// ... run performance audit ...

// Test offline handling
await SetNetworkThrottle("Offline");
await Click("#refresh-data");
await AssertPageContains("No internet connection");

// Restore full speed
await ClearNetworkThrottle();
```

---

## Network Mocking (Fault Injection)

Intercept network requests and return fake responses. Powerful for testing how the frontend handles errors, slow APIs, and edge cases.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `MockResponse(urlPattern, ...)` | `string urlPattern, int statusCode = 200, string? body = null, string? method = null, Dictionary<string, string>? headers = null, int delayMs = 0` | `void` | Add a mock rule |
| `RemoveMock(urlPattern)` | `string urlPattern` | `void` | Remove a mock rule |
| `ClearMocks()` | -- | `void` | Remove all mock rules |
| `GetMockRules()` | -- | `List<MockRule>` | List all active mock rules |

**URL pattern:** Use `*` as wildcard (glob). `"*/api/users*"` matches any URL containing `/api/users`. Without wildcards, plain substring matching is used.

```csharp
// Test: What happens when the API returns a 500 error?
MockResponse("/api/users", statusCode: 500,
    body: "{\"error\": \"Internal Server Error\"}");
await Click("#load-users");
await WaitForIdle();
await AssertPageContains("Something went wrong", "Shows error message on 500");
ClearMocks();

// Test: What happens when the API is slow?
MockResponse("/api/data", statusCode: 200,
    body: "{\"items\": []}", delayMs: 5000);
await Click("#refresh");
await Sleep(1000);
await AssertPageContains("Loading", "Shows loading state for slow response");
ClearMocks();

// Test: Rate limiting
MockResponse("*/api/submit*", statusCode: 429, method: "POST",
    body: "{\"error\": \"Too many requests\"}");
await Click("#submit");
await WaitForIdle();
await AssertPageContains("try again", "Shows rate limit message");
ClearMocks();

// Test: Specific response data
MockResponse("/api/profile", statusCode: 200,
    body: "{\"name\": \"Test User\", \"email\": \"test@example.com\"}");
await Navigate("https://example.com/profile");
await WaitForIdle();
await AssertPageContains("Test User", "Shows mocked user name");
ClearMocks();
```

---

## Network Interception (Breakpoints)

Intercept network requests and hold them until you decide to continue, fulfill with a custom response, or abort. Unlike mock rules (which auto-respond), breakpoints pause the request and wait for a decision via script, REST API, or the GUI.

### Intercept Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `AddInterceptRule(urlPattern, method?)` | `string urlPattern, string? method = null` | `void` | Add a breakpoint rule. `urlPattern` is a **regex** matched against the full URL. |
| `RemoveInterceptRule(urlPattern)` | `string urlPattern` | `void` | Remove a breakpoint rule |
| `ClearInterceptRules()` | -- | `void` | Remove all breakpoint rules and release any pending requests |
| `GetInterceptRules()` | -- | `List<InterceptRule>` | List all active breakpoint rules |
| `GetPendingRequests()` | -- | `List<PendingRequest>` | List currently held requests |
| `ResolvePendingRequest(requestId, decision)` | `int requestId, InterceptDecision decision` | `bool` | Resolve a pending request (continue, fulfill, or abort). Returns false if not found. |

**InterceptRule properties:** `UrlPattern` (string), `Method` (string?)

**PendingRequest properties:** `Id` (int), `Url` (string), `Method` (string), `Headers` (Dictionary), `ResourceType` (string), `MatchedPattern` (string), `Timestamp` (DateTime)

**InterceptAction enum:** `InterceptAction.Continue`, `InterceptAction.Fulfill`, `InterceptAction.Abort`

**InterceptDecision properties:**
- `Action` (InterceptAction) -- what to do
- `ModifiedUrl`, `ModifiedMethod`, `ModifiedHeaders` -- for Continue (modify request before forwarding)
- `StatusCode`, `Body`, `ResponseHeaders` -- for Fulfill (custom response)

Pending requests auto-continue after **120 seconds** if not resolved.

```csharp
// Set a breakpoint on user API calls
AddInterceptRule("/api/users");

// Trigger a request (e.g. click a button that calls the API)
await Click("#load-users");

// Wait for the request to be intercepted
await Sleep(1000);
var pending = GetPendingRequests();
Assert.True(pending.Count > 0, "Request was intercepted");

// Fulfill with a custom error response
ResolvePendingRequest(pending[0].Id, new InterceptDecision
{
    Action = InterceptAction.Fulfill,
    StatusCode = 500,
    Body = "{\"error\": \"Simulated failure\"}",
    ResponseHeaders = new Dictionary<string, string> { ["Content-Type"] = "application/json" }
});

await WaitForIdle();
await AssertPageContains("Something went wrong", "Shows error on 500");

// Clean up
ClearInterceptRules();
```

> **Note:** Breakpoints are most useful via the REST API or MCP tools, where an external agent (LLM or human) can inspect and decide per-request. In scripts, mock rules (`MockResponse`) are usually simpler for testing error states.

---

## WebMCP Tool Discovery

Trowser automatically detects tools registered by web pages via `navigator.modelContext` (the W3C Web Model Context API). When a page registers tools using `registerTool()` or `provideContext()`, Trowser intercepts them and makes them available for discovery and invocation.

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `GetWebMcpTools()` | -- | `Task<List<Dictionary<string, object>>>` | List all WebMCP tools on the current page (name, description, inputSchema, annotations) |
| `CallWebMcpTool(name, args?)` | `string toolName, Dictionary<string, object>? arguments` | `Task<Dictionary<string, object>>` | Call a WebMCP tool's execute function and return the result |

```csharp
// Discover tools on the page
var tools = await GetWebMcpTools();
Log($"Found {tools.Count} WebMCP tools");
foreach (var tool in tools)
    Log($"  {tool["name"]}: {tool["description"]}");

// Call a tool
if (tools.Any(t => t["name"]?.ToString() == "add_to_cart"))
{
    var result = await CallWebMcpTool("add_to_cart", new Dictionary<string, object>
    {
        ["productId"] = "abc123",
        ["quantity"] = "2"
    });
    Log($"Tool result: {result}");
}
```

WebMCP tools are also surfaced in the `GetSnapshot()` response when detected, so the built-in AI assistant automatically sees them.

---

## Network Body Capture

Network entries now include request and response bodies for API-like requests (Fetch, JSON, XML). Bodies are automatically captured and capped at 100KB.

### NetworkEntry Body Properties

| Property | Type | Description |
|----------|------|-------------|
| `RequestBody` | `string?` | Request body for POST/PUT/PATCH (null for GET/HEAD) |
| `ResponseBody` | `string?` | Response body for Fetch/JSON/XML types (null for images, scripts, etc.) |

```csharp
await Click("#save-btn");
var req = await WaitForRequest("/api/users", 5000);
Assert.Equal("POST", req.Method);
Assert.Equal(200, req.StatusCode);

// Inspect the response body
if (req.ResponseBody != null)
{
    Assert.Contains("\"id\":", req.ResponseBody, "Response includes generated ID");
}

// Check all API responses for a pattern
var apiCalls = Network.FindByUrl("/api/");
foreach (var call in apiCalls.Where(c => c.IsError))
{
    Log($"API error: {call.StatusCode} {call.Path}");
    if (call.ResponseBody != null)
        Log($"  Body: {call.ResponseBody.Substring(0, Math.Min(call.ResponseBody.Length, 200))}");
}
```

---

## Viewport (Responsive Design Testing)

Set the browser viewport size to test responsive layouts at different screen sizes. Uses Chrome DevTools Protocol device emulation — only the page rendering viewport changes, the Trowser window stays the same.

### Viewport Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `SetViewport(width, height)` | `Task` | Set exact viewport dimensions in pixels. |
| `SetViewport(preset)` | `Task` | Set viewport to a named preset. |
| `ResetViewport()` | `Task` | Reset to full screen (same as `SetViewport("Desktop")`). |
| `GetViewportSize()` | `Task<(int Width, int Height)>` | Get the current effective viewport size. |

### Presets

| Preset | Width | Height | Use Case |
|--------|-------|--------|----------|
| `"SmallPhone"` | 320 | 568 | iPhone SE / small Android |
| `"BigPhone"` | 412 | 915 | iPhone 15 / modern Android |
| `"LandscapePhone"` | 844 | 390 | iPhone 14 / modern Android |
| `"SmallPad"` | 768 | 1024 | iPad / small tablet (portrait) |
| `"BigPad"` | 1024 | 1366 | iPad Pro / large tablet (portrait) |
| `"Desktop"` | *(reset)* | *(reset)* | Full screen — clears the override |
| `"BigDesktop"` | 1920 | 1080 | Full HD monitor |

### Examples

```csharp
// Test a page at different viewport sizes
await Navigate("https://example.com");

// Use a preset
await SetViewport("SmallPhone");
await AssertPageContains("Menu");  // verify mobile menu is present
await AssertAccessible("AA");

// Use exact dimensions
await SetViewport(1440, 900);
var (w, h) = await GetViewportSize();
Log($"Viewport is {w}×{h}");

// Test all responsive breakpoints
var presets = new[] { "SmallPhone", "BigPhone", "LandscapePhone", "SmallPad", "BigPad", "Desktop", "BigDesktop" };
foreach (var preset in presets)
{
    Assert.Section(preset);
    await SetViewport(preset);
    await Sleep(500);
    await AssertPageContains("Welcome");
    await AssertAccessible("AA");
}

// Reset when done
await ResetViewport();
```

---

## Screen Curtain (Blind Testing)

Cover the web content with a black overlay so the page is invisible — useful for experiencing a site the way a blind user would, relying on a screen reader and keyboard. Toggle with **Ctrl+B** in the GUI (B for blind).

The overlay blocks mouse interaction with the page but does not remove content from the browser accessibility tree. Keyboard focus and screen reader output continue to work.

### Screen Curtain Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `ToggleScreenCurtain()` | `Task<bool>` | Toggle the curtain. Returns the new enabled state. |
| `SetScreenCurtain(enabled)` | `Task<bool>` | Enable (`true`) or disable (`false`) the curtain. Returns the new state. |
| `ScreenCurtainEnabled` | `bool` | Whether the curtain is currently active (read-only). |

### Examples

```csharp
// Turn on blind mode, explore with a screen reader, then turn off
await SetScreenCurtain(true);
var srText = await GetScreenReaderTexts();
Log(srText);

await ToggleScreenCurtain();  // off
Log($"Curtain enabled: {ScreenCurtainEnabled}");
```

---

## Tab Management

Trowser supports multiple browser tabs. Each tab has its own isolated state (console, network, mocks, refs). All automation methods operate on the active tab.

### Tab Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `NewTab(url?)` | `Task<int>` | Open a new tab (becomes active). Returns the new tab's index. |
| `CloseTab(tabIndex?)` | `Task` | Close a tab by index. Defaults to the active tab. Cannot close the last tab. |
| `SwitchTab(tabIndex)` | `void` | Switch the active tab. All subsequent calls target this tab. |
| `GetTabs()` | `List<TabInfo>` | List all tabs with `Index`, `Id`, `Title`, `Url`, `IsActive`. |
| `GetTabCount()` | `int` | Number of open tabs. |
| `GetActiveTabIndex()` | `int` | Index of the currently active tab. |

### Examples

```csharp
// Open a second tab and navigate it
var tab2 = await NewTab("https://example.com");
await WaitForElement("h1");

// Switch back to first tab
SwitchTab(0);
var url = await GetCurrentUrl();
Log($"First tab is at: {url}");

// List all tabs
var tabs = GetTabs();
foreach (var t in tabs)
    Log($"[{t.Index}]{(t.IsActive ? " *" : "")} {t.Title} — {t.Url}");

// Test two pages in parallel tabs
var indexA = await NewTab("https://site-a.com");
var indexB = await NewTab("https://site-b.com");

SwitchTab(indexA);
await AssertPageContains("Site A");

SwitchTab(indexB);
await AssertPageContains("Site B");

// Close extra tabs
await CloseTab(indexB);
await CloseTab(indexA);
```

### State Isolation

Each tab has its own:
- **Console log** -- `Console.Find(...)` and `GetConsoleErrors()` only search the active tab's messages
- **Network log** -- `Network.FindErrors()` and `FindRequests(...)` only search the active tab's traffic
- **Mock rules** -- `MockResponse(...)` applies to the active tab only
- **Element refs** -- Ref numbers and `RefGeneration` are independent per tab

---

## Page Inspection (Exploratory Testing)

All return `List<Dictionary<string, string>>`.

| Method | Description |
|--------|-------------|
| `GetLinks()` | All links: `href`, `text`, `target` |
| `GetHeadings()` | All h1-h6: `level`, `text`, `visible` (True/False) |
| `GetImages()` | All images: `src`, `alt`, `hasAlt`, `width`, `height` |
| `GetFormFields()` | All inputs: `tag`, `type`, `name`, `id`, `value`, `label`, `required`, `placeholder` |
| `GetMetaTags()` | All meta: `name`, `content`, `charset` |

### LLM Integration Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `GetSnapshot(fullText?, textSelector?)` | `Dictionary<string, object>` | Full page state (same as `GET /api/state`): URL, title, headings, interactive elements, errors. Pass `fullText: true` for untruncated text, `textSelector` for scoped text. |
| `GetInteractiveElements()` | `List<Dictionary<string, object>>` | All interactive elements with ref numbers and visibility. Automatically retries once after a short delay if the scan returns empty (handles DOM mutation timing). |
| `GetRefsInContainer(selector, elements)` | `HashSet<int>` | Returns ref numbers of elements inside a CSS container. Pass the result of `GetInteractiveElements()` as `elements`. |

```csharp
var headings = await GetHeadings();
foreach (var h in headings.Where(h => h["visible"] == "True"))
    Log($"{h["level"]}: {h["text"]}");

var images = await GetImages();
var missingAlt = images.Where(i => i["hasAlt"] == "False").ToList();
Assert.Equal(0, missingAlt.Count, "All images have alt text");
```

**Filtering interactive elements in scripts:**

The REST API (`GET /api/state`) supports filtering via query parameters (`tag`, `type`, `q`, `limit`, `selector`, `sections`). In C# scripts, use LINQ on the result of `GetInteractiveElements()`:

```csharp
var elements = await GetInteractiveElements();

// Filter by tag
var buttons = elements.Where(e => e["tag"].ToString() == "button").ToList();

// Filter by type/role
var checkboxes = elements.Where(e => e["type"].ToString() == "checkbox").ToList();

// Text search
var submitBtns = elements.Where(e =>
    (e["label"]?.ToString() ?? "").Contains("submit", StringComparison.OrdinalIgnoreCase)).ToList();

// CSS containment: only elements inside .product-card
var refsInCard = await GetRefsInContainer(".product-card", elements);
var cardElements = elements
    .Where(e => e["ref"] is JsonElement je && refsInCard.Contains(je.GetInt32()))
    .ToList();

// Combine filters with limit
var firstFiveCardButtons = elements
    .Where(e => e["tag"].ToString() == "button")
    .Where(e => e["ref"] is JsonElement je && refsInCard.Contains(je.GetInt32()))
    .Take(5)
    .ToList();
```

---

## Resource Management

Scripts run in the Roslyn scripting engine with `AutomationContext` as the global scope. Variables created during script execution consume memory until the script completes. After execution, the engine triggers a background garbage collection automatically.

### Explicit Cleanup

| Method | Description |
|--------|-------------|
| `CollectGarbage()` | Force garbage collection to free memory from script variables |
| `ClearNetworkLog()` | Clear the network log (can grow very large on traffic-heavy pages) |
| `ClearConsoleLog()` | Clear the console log |
| `await ClearAll()` | Reset all test session state (see below) |
| `await ClearAll(preserve)` | Reset with a whitelist — keep named categories intact |
| `await ClearSession()` | Lighter reset — clears test artifacts, preserves cookies and storage |

### ClearAll — Full Session Reset

`ClearAll()` clears all test session state in one call. Use between test sessions, at the start of a script, or to recover from leftover state after interrupted tests.

Pass a `preserve` set to keep specific categories intact:

```csharp
// Full reset
var result = await ClearAll();
Log(result.Summary);
// "Cleared: console, network, mocks, intercepts, assertions, cookies, throttle, viewport, localStorage, sessionStorage (10 items)"

// Preserve cookies and storage (avoid destroying session)
var safe = await ClearAll(new HashSet<string> { "cookies", "storage" });
Log(safe.Summary);
// "Cleared: console, network, mocks, intercepts, assertions, throttle, viewport (7 items). Preserved: cookies, storage"

// Lighter alternative: ClearSession() = ClearAll with cookies + storage preserved
var session = await ClearSession();
Log(session.Summary);
```

| Preserve value | What it keeps |
|----------------|---------------|
| `cookies` | Browser cookies |
| `storage` | Both localStorage and sessionStorage |
| `mocks` | Mock rules |
| `intercepts` | Intercept rules |
| `throttle` | Network throttle |
| `viewport` | Viewport override |

Console log, network log, and assertions are **always cleared** (not preservable).

**What ClearAll clears (default — no preserve):**

| State | Equivalent to |
|-------|---------------|
| Console log | `ClearConsoleLog()` |
| Network log | `ClearNetworkLog()` |
| Mock rules | `ClearMocks()` |
| Intercept rules | `ClearInterceptRules()` |
| Assertions | `Assert.Reset()` |
| Cookies | `ClearCookies()` |
| Network throttle | `ClearNetworkThrottle()` |
| Viewport override | `ResetViewport()` |
| localStorage | `ClearStorage("local")` |
| sessionStorage | `ClearStorage("session")` |

Also available as a button ("Clear All") in the Script Console toolbar, and via the `POST /api/clear-all` (with optional `preserve` body) and `POST /api/clear-session` REST endpoints, or the `browser_clear_all` / `browser_clear_session` MCP tools.

### Best Practices

```csharp
// After working with large datasets, clear them explicitly
var entries = GetNetworkLog();
// ... analyze entries ...
entries = null;
ClearNetworkLog();
CollectGarbage();
```

For long-running scripts that process multiple pages, call `ClearNetworkLog()` between pages to prevent unbounded memory growth.

---

## Error Handling Summary

| Method | Not Found Behavior |
|--------|--------------------|
| `Click`, `Type`, `Select`, `Hover`, `GetText`, `GetAttribute`, `GetProperty`, `IsChecked` | Throws `InvalidOperationException` |
| `PressKey` | Throws `InvalidOperationException` if selector given and not found |
| `Scroll` | Throws `InvalidOperationException` if selector given and not found |
| `Exists` | Returns `false` |
| `Count` | Returns `0` |
| `WaitForElement`, `WaitForRequest` | Throws `TimeoutException` |
| `WaitForNavigation`, `WaitForIdle` | Returns `false` on timeout (does not throw) |
| `WaitForFinalNavigation` | Returns `0` on timeout (does not throw) |
| `Navigate` | Logs warning, does not throw |
| `Fetch` | Throws `InvalidOperationException` on network/CORS failure |
| `GetCookie` | Returns `null` if not found |
| `MockResponse`, `RemoveMock`, `ClearMocks` | Never throws |
| `AddInterceptRule`, `RemoveInterceptRule`, `ClearInterceptRules` | Never throws |
| `ResolvePendingRequest` | Returns `false` if request ID not found |
| `ClearAll`, `ClearSession` | Individual clear operations that fail are silently skipped; always returns a result |
| Page inspection methods | Returns empty list on parse failure |

---

## Complete Script Template

```csharp
// === Test: [Test Name] ===
await Navigate("https://example.com");
await WaitForElement("h1");

// --- Page Structure ---
Assert.Section("Page Structure");
Assert.True(await Exists("h1"), "Has h1 heading");
Assert.Contains("Expected Title", await GetTitle(), "Page title");

// --- Interaction ---
Assert.Section("Form Interaction");
await Type("#email", "test@example.com");
await Click("#submit");
await WaitForNavigation(5000);
Assert.Contains("success", await GetCurrentUrl(), "Navigated to success page");

// Wait for page to fully settle after navigation
await WaitForIdle(500, 5000);

// --- Keyboard & Focus ---
await PressKey("Tab");
await PressKey("Enter", "#dialog-confirm");
await PressKey("Escape");

// --- Scroll & Hover ---
await Scroll(direction: "down");
await Hover("#info-icon");
await Scroll("#footer", scrollIntoView: true);

// --- Read Content (shadow DOM safe) ---
var heading = await GetText("h1");
Assert.NotEmpty(heading, "Heading has text");

// --- Page Text ---
await AssertPageContains("Welcome");
await AssertPageNotContains("Error");

// --- Error Checks ---
Assert.Section("Error Checks");
Assert.Equal(0, GetConsoleErrors().Count, "No JS errors");
Assert.Equal(0, Network.FindErrors().Count, "No HTTP errors");

// --- Cookies ---
Assert.Section("Cookie Security");
var session = await GetCookie("sessionId");
if (session != null)
{
    Assert.True((bool)session["secure"], "Session cookie is Secure");
    Assert.True((bool)session["httpOnly"], "Session cookie is HttpOnly");
}

// --- Fault Injection ---
Assert.Section("Error Handling");
MockResponse("/api/data", statusCode: 500, body: "{\"error\": \"fail\"}");
await Click("#load-data");
await WaitForIdle();
await AssertPageNotContains("unhandled", "No unhandled errors on 500");
ClearMocks();

// --- Accessibility ---
Assert.Section("Accessibility");
await AssertAccessible("AA");

// --- Performance ---
Assert.Section("Performance");
await AssertPerformance();
await AssertPerformanceMetric("LCP", 2500, "LCP under 2.5s");

// --- Security ---
Assert.Section("Security");
await AssertSecure();
await AssertSecurityHeaders(minSeverity: Severity.Medium);
await AssertCors(minSeverity: Severity.Medium);

await Screenshot("test-result.png");
// Summary auto-prints with per-section breakdown
```
