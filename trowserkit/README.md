# Trowser

A Windows web browser built for testing web services. Combines a WebView2-based browser with a built-in C# scripting engine for test automation -- like a browser and Selenium in one. Supports both an interactive GUI and a headless CLI mode for automated testing (including LLM-driven testing via APIs).

## Prerequisites

- **Windows 10/11** (x64)
- **.NET 8 SDK** -- [download here](https://dotnet.microsoft.com/download/dotnet/8.0)
- **WebView2 Runtime** -- pre-installed on Windows 10/11. If missing, [download here](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) or find/request a version with bundled WebView.
- **Should run on emulators** (Wine/Crossover)

## Windows SmartScreen

If you downloaded Trowser as a signed release and see a "Windows protected your PC" or "Unknown publisher" warning, you can "Run anyway" once and it will work after that. If you still have problems, see **SMARTScreen.md** on how to install the certificate (one-time) to avoid warnings.

## Credits and Contact

Trowser has been built by Rikard Edgren, well aided by Claude Opus and composer. Fast technical testing made possible by axe-core, Retire.js, html-validate, web.vitals and gremlins.js.
The solution was made possible by all people who helped me learn exploratory testing since 1998, especially thetesteye companions Henrik Emilsson and Martin Jansson, and also field legends like Cem Kaner, James Bach, Michael Bolton and Elisabeth Hendrickson.
Guidance during the development (4 weeks to version 1.0) was provided by Pär Holmdahl, Henrik Emilsson, Magnus Florén, and Pär Tojkander.
Big thanks to the Trowser Alpha Group: Christopher Edeson, and Roger Ringström.
Creator can be reached at thetesteye.com, LinkedIn, or rikard.edgren@thetesteye.com.

## Privacy

Trowser does **not** collect telemetry, analytics, or usage data of any kind. No information is sent to Trowser's developers or any third party.

Network requests made by Trowser:
- **Web pages you visit** -- standard browser traffic, routed through WebView2 (Chromium).
- **LLM API calls** -- only when you configure an LLM provider in Settings. Sent to the endpoint you specify (OpenRouter, OpenAI, Anthropic, GitHub Copilot, or a local model such as Ollama). Keys can also come from `OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`. Trowser sends page snapshots and tool results to the LLM; no data is sent without your explicit action.
- **Retire.js vulnerability database** -- during security scans, Trowser checks GitHub (`api.github.com`) for a newer version of the Retire.js database. No user data is included in this request; it is a simple version check cached for 12 hours.
- **Proxy** -- if configured, all browser traffic is routed through your specified proxy (e.g. OWASP ZAP). No proxy is used by default.

All data stays on your machine. Settings are stored locally in `%APPDATA%\Trowser\`. Diagnostic logs are written to `%APPDATA%\Trowser\trowser.log`.

## Known bugs

- Chat Window "x" can only close a chat session, not the whole panel
- Monkey test can report fewer actions than requested, without logging
- POST /api/load-test Sends Requests Without Session Cookies (if logged in, use /api/execute-js with fetch() instead)
- The intercept mechanism uses browser-level request interception and may not work in all situations
- Menu has partial white lines between sections
- License in About dialog looks like a link, but isn't
- Session Log dialog has incorrect tab order

### LLM Integration

Trowser supports two modes of LLM interaction:

#### Mode 1: Real-Time API (interactive)
When Trowser runs in GUI mode, it starts an embedded HTTP API server on `localhost:6923`. An LLM agent can connect to a live Trowser instance and interact with the browser in real-time: observe the page, click elements, fill forms, run assertions, and iterate based on results.

**Workflow:**
1. Open Trowser, navigate to the page you want to test, activate REST API in status bar
2. Give the LLM the api references, URL and API endpoint, vital information and instructions how to test
3. The LLM calls `GET http://localhost:6923/api/state` to see the page
4. The LLM decides what to test, executes actions via the API, observes results, and iterates
5. The LLM reports findings to you

Examples of LLM instructions are available in trowserkit folder. Remember to include testheuristics.md and tailor it to your needs.
Copilot instructions are provided in `.github/copilot-instructions.md`.
A Cursor rule file is provided at `.cursor/rules/trowser.mdc` (see also `trowserkit/trowser.mdc` for distribution).
Make your own for your context.

#### Mode 2: Chat Window
Trowser GUI has a Chat window where instructions can be given to an LLM (setup in Settings).
Commands are sent with structured tool calling, and passes along API instructions and test heuristics.
This is not the recommended workflow, external calls with REST API provides much better ways to inform the LLM, and reports are easier to read (.html works good).

## CLI Scripts (batch)
Write a `.csx` script, run it, read the output. Good for predefined test suites.

```bash
Trowser.exe --run tests/smoke.csx --url https://example.com
```

## CLI Mode

Run test scripts from the command line without any GUI interaction. The browser window is hidden by default. This is the mode used for automated and LLM-driven testing.

### Syntax

```bash
Trowser.exe --run <script.csx> [--url <url>] [--output <file>] [--visible] [--timeout <seconds>]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--run <script.csx>` | **Required.** Path to a C# script file to execute. | -- |
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

For full scripting reference (Quicktests, recording, semantic locators, performance, security, mocking, etc.), see **[scripting-reference.md](scripting-reference.md)**.

### Examples

```bash
# Run a test script against a URL
Trowser.exe --run tests/smoke.csx --url https://example.com

# Run with visible window for debugging
Trowser.exe --run tests/smoke.csx --url https://example.com --visible

# Save output to a file with a longer timeout
Trowser.exe --run tests/full-suite.csx --url https://example.com --output report.txt --timeout 300
```

## Features
- Documentation below isn't 100% up-to-date, but give you the basics. See references documents for full documentation.

### Browser
- Address bar with URL entry (Enter to navigate, or type a search query)
- Back / Forward / Refresh / Stop navigation buttons
- Page title in the window title bar
- Status bar showing load status and current URL
- F12 to open Chrome DevTools
- Search with Ctrl+F

### Script Console
Toggle with **Ctrl+0** or the button in the nav bar. Write C# scripts that control the browser directly.

Scripts run with full async/await support. The automation API methods are available as top-level functions.

### Test Assertions
Built-in assertion library with colored pass/fail output. Assertions don't throw -- they log results and continue, so all tests in a script run to completion. A summary is printed automatically at the end.

```csharp
await Navigate("https://example.com");

// Assertions
var title = await GetTitle();
Assert.Equal("Example Domain", title, "Page title should match");
Assert.True(await Exists("h1"), "Page should have an h1 heading");

var heading = await GetText("h1");
Assert.Contains("Example", heading, "Heading should contain 'Example'");
Assert.NotEmpty(await GetPageSource(), "Page should have content");

// Summary is printed automatically: PASSED 4/4
```

### Console Capture
Browser `console.log`, `console.warn`, `console.error`, and `console.info` messages are automatically captured and displayed in the script output with color coding. Unhandled JS errors and promise rejections are also caught.

```csharp
await Navigate("https://example.com");
await ExecuteJs("console.log('hello from page')");
await ExecuteJs("console.error('something went wrong')");

// Query captured console messages
var errors = GetConsoleErrors();
Assert.Equal(1, errors.Count, "Should have 1 console error");

// Print all console messages
PrintConsoleLog();
```

### Network Logging
All HTTP requests/responses are automatically captured with method, URL, status code, headers, and resource type. Query them programmatically in scripts.

```csharp
ClearNetworkLog();
await Navigate("https://example.com");
await Sleep(1000);

// Print all captured network traffic
PrintNetworkLog();

// Query specific requests
var apiCalls = FindRequests("/api/");
var errors = Network.FindErrors();
var scripts = Network.FindByType("Script");

// Wait for a specific request to appear
var response = await WaitForRequest("/api/data", timeoutMs: 5000);
Assert.True(response.IsSuccess, "API call should succeed");
Assert.Equal(200, response.StatusCode);

// Check for no HTTP errors
Assert.Equal(0, errors.Count, "Should have no HTTP errors");
```

### WCAG Accessibility Checker
Built-in accessibility auditing powered by [axe-core](https://github.com/dequelabs/axe-core). Checks pages against WCAG 2.0/2.1/2.2 guidelines and returns structured, actionable results.

```csharp
await Navigate("https://example.com");

// Quick check: assert the page is WCAG AA accessible
await AssertAccessible("AA");

// Get detailed results
var results = await CheckAccessibility("AA");
Log($"Violations: {results.ViolationCount}, Passes: {results.PassCount}");

// Print a full formatted report with color-coded impact levels
await PrintAccessibilityReport("AA");

// Filter by impact severity
var critical = results.GetCritical();  // serious + critical only
var byLevel = results.GetByWcagLevel("AA");

// Inspect individual violations
foreach (var v in results.Violations)
{
    Log($"[{v.Impact}] {v.RuleId}: {v.Help}");
    Log($"  WCAG: {string.Join(", ", v.WcagCriteria)}");
    Log($"  Elements: {v.Count}");
    Log($"  More info: {v.HelpUrl}");
}

// Check only a section of the page
var navResults = await CheckAccessibility("AA", selector: "nav");

// Check at different WCAG levels
var levelA = await CheckAccessibility("A");
var levelAAA = await CheckAccessibility("AAA");

// Assert with minimum impact filter (ignore minor issues)
await AssertAccessible("AA", minImpact: Impact.Serious);
```

### Example: Full Test Script
```csharp
// Full example: test a web page
await Navigate("https://example.com");
await WaitForElement("h1");

// Test page structure
Assert.True(await Exists("h1"), "Has heading");
Assert.Contains("Example", await GetText("h1"), "Heading text");
Assert.Contains("Example Domain", await GetTitle(), "Page title");

// Test no console errors
Assert.Equal(0, GetConsoleErrors().Count, "No JS errors");

// Test no HTTP errors
Assert.Equal(0, Network.FindErrors().Count, "No HTTP errors");

// Test WCAG accessibility
await AssertAccessible("AA");

// Screenshot for reference
await Screenshot("test-result.png");

// Summary is auto-printed at the end
```

## Automation API Reference

All methods are async and available directly in scripts.

### Navigation

| Method | Description |
|--------|-------------|
| `Navigate(url)` | Navigate to a URL and wait for page load |
| `GoBack()` | Navigate back in history |
| `GoForward()` | Navigate forward in history |
| `GetCurrentUrl()` | Get the current page URL |
| `GetTitle()` | Get the current page title |
| `GetPageSource()` | Get the full HTML source of the page |
| `GetPageText()` | All visible text on the page (`document.body.innerText`) |

### Element Interaction

All interaction methods support **CSS selectors** and **semantic locators** (`ByRole`, `ByLabel`, `ByText`, `ByPlaceholder`, `ByTestId`). Auto-wait for visible/enabled (default 5s). See [scripting-reference.md](scripting-reference.md) for details.

| Method | Description |
|--------|-------------|
| `Click(selector)` | Click an element by selector or locator |
| `Type(selector, text)` | Clear and type text into an input element |
| `Select(selector, value)` | Select a dropdown option by value |
| `Hover(selector)` | Hover over an element (triggers tooltips/menus) |
| `PressKey(key, selector?, modifiers?)` | Send keyboard key press |
| `Scroll(selector?, direction, scrollIntoView)` | Scroll page/element. Directions: `up`, `down`, `top`, `bottom`. Set `scrollIntoView: true` to scroll an element into view. |

### Element Inspection

| Method | Description |
|--------|-------------|
| `GetText(selector)` | Get the inner text of an element (pierces shadow DOM) |
| `GetAttribute(selector, attribute)` | Get an attribute value of an element (pierces shadow DOM) |
| `GetProperty(selector, prop)` | Get live DOM property (e.g. `value`, `checked`) |
| `IsChecked(selector)` | Whether a checkbox/toggle is checked |
| `Exists(selector)` | Check if an element exists (returns bool) |
| `Count(selector)` | Count elements matching a selector |
| `Extract(selector, fields...)` | Extract structured data from tables/repeating elements |

### Waiting

| Method | Description |
|--------|-------------|
| `WaitForElement(selector, timeoutMs?)` | Wait until an element appears in the DOM (default timeout: 10s) |
| `WaitForRequest(urlSubstring, timeoutMs?)` | Wait for a network request matching the URL (default timeout: 10s) |
| `WaitForNavigation(timeoutMs?)` | Wait for a page navigation event to complete (default timeout: 10s) |
| `WaitForFinalNavigation(quietPeriodMs?, timeoutMs?)` | Wait for redirect chains (SAML, OAuth, SSO) to settle |
| `WaitForIdle(quietPeriodMs?, timeoutMs?)` | Wait until network is quiet and animations stop |
| `Sleep(ms)` | Pause script execution for the specified duration |

### Test Assertions (`Assert.`)

Assertions log results inline and don't throw. A summary is printed automatically after the script completes.

| Method | Description |
|--------|-------------|
| `Assert.True(condition, message?)` | Assert condition is true |
| `Assert.False(condition, message?)` | Assert condition is false |
| `Assert.Equal(expected, actual, message?)` | Assert two values are equal |
| `Assert.NotEqual(expected, actual, message?)` | Assert two values are not equal |
| `Assert.Contains(substring, actual, message?)` | Assert string contains substring |
| `Assert.NotContains(substring, actual, message?)` | Assert string does not contain substring |
| `Assert.Matches(pattern, actual, message?)` | Assert string matches regex pattern |
| `Assert.Null(value, message?)` | Assert value is null |
| `Assert.NotNull(value, message?)` | Assert value is not null |
| `Assert.NotEmpty(value, message?)` | Assert string is not null or empty |
| `Assert.GreaterThan(expected, actual, message?)` | Assert actual > expected |
| `Assert.LessThan(expected, actual, message?)` | Assert actual < expected |
| `Assert.CountEquals(count, collection, message?)` | Assert collection has expected count |
| `Assert.Pass(message)` | Unconditional pass |
| `Assert.Fail(message)` | Unconditional fail |
| `Assert.Section(name)` | Start a named test section (groups assertions in summary) |
| `Assert.Summary()` | Print pass/fail summary (auto-called) |
| `Assert.Reset()` | Reset all assertion results |

**Page text assertions:** `AssertPageContains(text)` and `AssertPageNotContains(text)` check visible page text.

### Console Capture

Browser console messages are captured automatically and appear in the output pane.

| Method | Description |
|--------|-------------|
| `GetConsoleLog()` | Get all captured console entries |
| `GetConsoleErrors()` | Get only error-level console entries |
| `ClearConsoleLog()` | Clear captured console entries |
| `PrintConsoleLog(maxEntries?)` | Print formatted console log to output |
| `Console.Find(text)` | Find entries containing text |
| `Console.GetWarnings()` | Get warning-level entries |
| `Console.HasErrors` | Check if any errors were logged (bool) |

### Network Logging

All network requests/responses are captured automatically.

| Method | Description |
|--------|-------------|
| `GetNetworkLog()` | Get all captured network entries |
| `FindRequests(urlSubstring)` | Find entries matching URL substring |
| `ClearNetworkLog()` | Clear captured network entries |
| `PrintNetworkLog(maxEntries?)` | Print formatted network log to output |
| `WaitForRequest(urlSubstring, timeoutMs?)` | Wait for a matching request |
| `Network.FindByUrl(urlSubstring)` | Match by URL |
| `Network.FindByMethod(method)` | Find entries by HTTP method |
| `Network.FindByStatus(statusCode)` | Find entries by status code |
| `Network.FindByType(resourceType)` | Find entries by type (Document, Script, etc.) |
| `Network.FindErrors()` | Find all 4xx/5xx responses |

Each `NetworkEntry` has: `Method`, `Url`, `StatusCode`, `ReasonPhrase`, `ResourceType`, `RequestHeaders`, `ResponseHeaders`, `ContentType`, `Path`, `Host`, `IsError`, `IsSuccess`, `RequestBody`, `ResponseBody` (for Fetch/XHR).

**Additional scripting features** (see [scripting-reference.md](scripting-reference.md)): Performance (Web Vitals), Security (Retire.js CVE scan), Security Headers, HTML validation, Monkey testing, Smart Monkey, Cookie management, Network mocking (`MockResponse`), Request interception (breakpoints), Viewport, Tab management, WebMCP tools.

### Accessibility (WCAG)

Powered by axe-core. Audits pages against WCAG 2.0/2.1/2.2 guidelines.

| Method | Description |
|--------|-------------|
| `CheckAccessibility(wcagLevel?, selector?)` | Run WCAG audit, returns `AccessibilityResult` |
| `PrintAccessibilityReport(wcagLevel?, includeNodes?, minImpact?)` | Run audit and print formatted color-coded report |
| `AssertAccessible(wcagLevel?, minImpact?, message?)` | Assert page has no violations (integrated with Assert) |

**`AccessibilityResult` properties:**

| Property/Method | Description |
|--------|-------------|
| `Violations` | List of `AccessibilityViolation` |
| `Passes` | List of rules that passed |
| `Incomplete` | Rules needing manual review |
| `ViolationCount` / `PassCount` | Counts |
| `IsClean` | True if no violations |
| `AffectedElementCount` | Total elements with violations |
| `GetCritical()` | Get serious + critical violations only |
| `GetByMinImpact(Impact)` | Filter by minimum impact level |
| `GetByWcagLevel(level)` | Filter by WCAG level (A, AA, AAA) |
| `Format(includeNodes?, minImpact?)` | Generate formatted text report |

**`AccessibilityViolation` properties:** `RuleId`, `Impact` (Critical/Serious/Moderate/Minor), `Description`, `Help`, `HelpUrl`, `Tags`, `Nodes`, `Count`, `WcagLevel`, `WcagCriteria`.

**WCAG levels:** `"A"`, `"AA"` (default), `"AAA"`, or `null` for all rules including best practices.

### Page Inspection (Exploratory Testing)

Helper methods that return structured data about the page, useful for exploratory testing and LLM-driven analysis.

| Method | Description |
|--------|-------------|
| `GetLinks()` | Get all links with href, text, and target |
| `GetHeadings()` | Get heading structure (h1-h6): `level`, `text`, `visible` |
| `GetImages()` | Get all images with src, alt, hasAlt, dimensions |
| `GetFormFields()` | Get all form inputs with tag, type, name, id, value, label, required |
| `GetMetaTags()` | Get all meta tags with name, content, charset |

Each returns `List<Dictionary<string, string>>`. Example:

```csharp
var images = await GetImages();
foreach (var img in images) {
    if (img["hasAlt"] == "False") Log($"Missing alt text: {img["src"]}");
}

var headings = await GetHeadings();
foreach (var h in headings) Log($"{h["level"]}: {h["text"]}");
```

### JavaScript & Screenshots

| Method | Description |
|--------|-------------|
| `ExecuteJs(script)` | Execute arbitrary JavaScript and return the result |
| `Screenshot(filePath)` | Capture the page as a PNG screenshot |

### Logging

| Method | Description |
|--------|-------------|
| `Log(message)` | Write a message to the script console output |

## Real-Time LLM API

When running in GUI mode, Trowser starts an HTTP API server on `http://localhost:6923`. This allows LLM agents (Cursor, ChatGPT, etc.) to interact with a live browser session. Trowser also implements **MCP** (Model Context Protocol) at `POST http://localhost:6923/mcp` for native integration with Cursor, Claude Desktop, and other MCP clients.

### Configuration

| Flag | Description |
|------|-------------|
| `--api-port <port>` | Override the default API port (default: 6923) |
| `--api` | Enable the API server on startup |
| `--no-api` | Disable the API server |
| `--api-key <key>` | Set a fixed API key (default: auto-generated each session) |
| `--safe` | Enable safe mode (blocks JS execution, C# scripting, mocking, cookie manipulation) |
| `--scope <patterns>` | Restrict navigation to matching URL patterns (comma-separated, `*.*` = no restrictions) |
| `--proxy <url>` | Route all browser traffic through a proxy (e.g. OWASP ZAP) |

The API is enabled by default in GUI mode and disabled in CLI mode (`--run`). See [Security](#security) for details on authentication and safe mode. Full API reference: **[trowser-api-reference.md](trowser-api-reference.md)**. Endpoint index (auto-generated): **[trowser-api-index.md](trowser-api-index.md)**. See **[DOCUMENTATION.md](DOCUMENTATION.md)** for the doc map.

### API Endpoints

All responses are JSON with the format `{ "success": true/false, "data": {...} }` or `{ "success": false, "error": "..." }`.

#### Page State (GET)

| Endpoint | Description |
|----------|-------------|
| `GET /api/state` | **Main endpoint.** Full page snapshot: URL, title, headings (with visibility), interactive elements (with ref numbers and visibility), console/network errors, assertions. Filtering: `?selector=CSS` (scope to container), `?tag=input`, `?type=checkbox`, `?q=search`, `?limit=N`, `?sections=interactiveElements,url`, `?fullText=true` |
| `GET /api/interactive` | All interactive elements with ref numbers, CSS selectors, and visibility |
| `GET /api/screenshot` | Capture screenshot, returns file path. Add `?base64=true` for base64 data |
| `GET /api/console` | Browser console messages |
| `GET /api/network` | Network traffic log. Filter with `?errors=true`, `?url=X`, `?method=GET`, `?status=404`, `?type=Script`, `?includeBody=true` |
| `GET /api/assertions` | Current test assertion results |
| `GET /api/info` | Server info, current URL, entry counts |
| `GET /api/ping` | Health check |
| `GET /api/page-text` | All visible page text |
| `GET /api/source` | Full page HTML source |

#### Actions (POST)

All action endpoints accept `{ "ref": N }` (preferred), `{ "selector": "..." }`, or **semantic locators** (`{"role":"button","name":"Submit"}`, `{"label":"Email"}`, `{"byText":"Sign in"}`, `{"placeholder":"Search..."}`, `{"testId":"submit-btn"}`).

| Endpoint | Body | Description |
|----------|------|-------------|
| `POST /api/navigate` | `{ "url": "..." }` | Navigate to a URL |
| `POST /api/click` | `{ "ref": N }` or locator. `button`, `clickCount` for right/double-click | Click an element |
| `POST /api/type` | `{ "ref": N, "text": "..." }` | Type into an input |
| `POST /api/select` | `{ "ref": N, "value": "..." }` | Select dropdown option |
| `POST /api/text` | `{ "ref": N }` | Get element inner text (pierces shadow DOM) |
| `POST /api/attribute` | `{ "ref": N, "attribute": "..." }` | Get element attribute (pierces shadow DOM) |
| `POST /api/property` | `{ "ref": N, "property": "value" }` | Get live DOM property (value, checked, etc.) |
| `POST /api/extract` | `{ "selector": "...", "fields": {...} }` | Extract structured data from tables/repeating elements |
| `POST /api/hover` | `{ "ref": N }` | Hover over element (triggers tooltips/menus) |
| `POST /api/scroll` | `{ "direction": "down" }` or `{ "ref": N, "scrollIntoView": true }` | Scroll page/element |
| `POST /api/key` | `{ "key": "Tab", "ref"?, "modifiers"? }` | Send keyboard key press |
| `POST /api/execute-js` | `{ "script": "..." }` | Execute JavaScript, return result |
| `POST /api/execute-script` | `{ "code": "..." }` | Execute a C# test script |
| `POST /api/wait` | `{ "selector": "...", "timeout": 10000 }` | Wait for element to appear |
| `POST /api/wait-for-navigation` | `{ "timeout": 10000 }` | Wait for page navigation after a click |
| `POST /api/wait-for-final-navigation` | `{ "quietPeriod": 500, "timeout": 15000 }` | Wait for redirect chains (SAML, OAuth) |
| `POST /api/wait-for-idle` | `{ "quietPeriod": 500, "timeout": 10000 }` | Wait until network quiet and animations stop |
| `POST /api/batch` | `{ "actions": [...] }` | Execute multiple actions in one request |
| `POST /api/accessibility` | `{ "level": "AA" }` | Run WCAG accessibility audit |
| `POST /api/performance` | `{}` | Measure Web Vitals |
| `POST /api/security` | `{}` | Scan for JS CVE vulnerabilities |
| `POST /api/security-headers` | `{}` | Analyze HTTP security headers |
| `POST /api/validate-html` | `{}` | Validate HTML markup |
| `POST /api/compatibility` | `{}` | Backward compatibility analysis |
| `POST /api/monkey-test` | `{ "actions", "delay", "seed" }` | Random robustness testing |
| `POST /api/smart-monkey` | `{ "followLinks", "maxPages", ... }` | Smart systematic robustness test |
| `POST /api/assert/*` | Various | Page-contains, element-visible, url, title, etc. |
| `POST /api/assert/reset` | *(empty)* | Reset assertion results |
| `POST /api/dialog/handle` | `{ "accept", "promptText"? }` | Configure native dialog handling (call before triggering) |
| `GET /api/dialog` | — | Inspect last native dialog |
| `GET/POST /api/cookies`, `/api/cookies/set`, `/api/cookies/delete`, `/api/cookies/clear` | — | Cookie management |
| `GET/POST /api/mock`, `/api/mock/remove`, `/api/mock/clear` | — | Network mocking (fault injection) |
| `GET/POST /api/intercept`, `/api/intercept/continue`, `/api/intercept/fulfill`, `/api/intercept/abort` | — | Request breakpoints |
| `GET/POST /api/viewport` | — | Viewport for responsive testing |
| `GET /api/tabs`, `POST /api/tabs/new`, `/api/tabs/close`, `/api/tabs/switch` | — | Tab management |
| `GET /api/webmcp`, `POST /api/webmcp/call` | — | WebMCP tool discovery and invocation |

### Interactive Elements

The `/api/state` and `/api/interactive` endpoints return all interactive elements on the page. Each element has a `ref` number for easy interaction and a `visible` flag to distinguish real content from hidden DOM artifacts:

```json
{
  "ref": 0,
  "tag": "input",
  "type": "text",
  "selector": "#username",
  "label": "Username",
  "value": "",
  "placeholder": "Enter your username",
  "enabled": true,
  "required": true,
  "visible": true
}
```

**Use `ref` numbers** in action endpoints: `{"ref": 0}` is simpler and avoids CSS selector escaping issues in shells. Hidden elements have `ref: -1` and `visible: false`.

### Example: LLM Testing Session

> **PowerShell note:** Use `Invoke-RestMethod` (alias `irm`) instead of `curl`. PowerShell aliases `curl` to `Invoke-WebRequest` which behaves differently.

```powershell
# 1. See what's on the page (interactive elements with ref numbers)
irm http://localhost:6923/api/state

# 2. Type into a form field using its ref number
irm http://localhost:6923/api/type -Method Post -ContentType "application/json" -Body '{"ref": 3, "text": "testuser"}'

# 3. Click a button using its ref number
irm http://localhost:6923/api/click -Method Post -ContentType "application/json" -Body '{"ref": 5}'

# 4. Wait for navigation after click
irm http://localhost:6923/api/wait-for-navigation -Method Post -ContentType "application/json" -Body '{"timeout": 5000}'

# 5. Check the result
irm http://localhost:6923/api/state

# 6. Read element text (pierces shadow DOM)
irm http://localhost:6923/api/text -Method Post -ContentType "application/json" -Body '{"ref": 0}'

# 7. Run accessibility audit
irm http://localhost:6923/api/accessibility -Method Post -ContentType "application/json" -Body '{"level": "AA"}'

# 8. Take a screenshot
irm http://localhost:6923/api/screenshot
```

### Scripting API: LLM Methods

These methods are also available in `.csx` scripts:

| Method | Description |
|--------|-------------|
| `GetSnapshot(fullText?, textSelector?)` | Get comprehensive page state (same as `/api/state`) |
| `GetInteractiveElements()` | Get all interactive elements with ref numbers and visibility |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+` | Toggle script console |
| F5 | Refresh page |
| F12 | Open DevTools |
| Ctrl+L | Focus address bar |
| Alt+Left | Go back |
| Alt+Right | Go forward |

## Security

Trowser is a **testing tool**, not a general-purpose web browser. Its API grants full control over a live browser session, which is powerful for testing but requires understanding the security model. See [SECURITY.md](SECURITY.md) for the full threat model.

### API Key Authentication

Every API request (except `GET /api/ping`) requires an API key via the `Authorization` header:

```
Authorization: Bearer trowser_a1b2c3d4e5...
```

A random API key is auto-generated each time the API server starts. Find it by hovering over the API status indicator in the status bar. For CI/CD or MCP client configurations where you need a stable key, use `--api-key <key>`.

### Safe Mode

Safe mode disables the most powerful (and dangerous) API operations. Enable it with `--safe` or toggle it in **Settings > Security**. When active, these are blocked:

| Blocked | Why |
|---------|-----|
| `POST /api/execute-js` | Arbitrary JavaScript can access cookies, tokens, DOM |
| `POST /api/execute-script` | C# scripts run in the host process |
| `POST /api/mock` | Network mocking can intercept/modify responses |
| `POST /api/cookies/*` | Cookie manipulation can hijack sessions |
| `browser_execute_js` (MCP) | Same as execute-js above |
| `browser_run_script` (MCP) | Same as execute-script above |

Safe mode does **not** block navigation, clicking, typing, screenshots, or read-only inspection -- these are needed for normal test automation.

### Navigation Guard

Restrict which URLs the browser can navigate to using `--scope`:

```bash
# Only allow your staging site
Trowser.exe --api --scope "https://*.myapp.com"

# Allow multiple specific sites
Trowser.exe --api --scope "https://staging.app.com, https://api.app.com"
```

Internal URLs (`about:`, `data:`, `blob:`) are always allowed. The scope can also be changed at runtime via **Settings > Browser > Navigation Scope**.

### Recommendations

- **Do not use Trowser as your daily web browser.** It is designed for testing.
- **Enable safe mode** (`--safe`) when testing untrusted or third-party sites.
- **Set a navigation scope** when you know which sites you'll be testing.
- **Use a fixed API key** (`--api-key`) in CI/CD pipelines for predictable authentication.

## Architecture

- **WPF** application shell with dark theme
- **WebView2** (Chromium) browser engine
- **Roslyn C# Scripting** for the built-in test automation engine
- **axe-core 4.10.3** for automated WCAG accessibility auditing
- **Embedded HTTP API** for real-time LLM interaction (localhost, port 6923)
- `AutomationContext` -- automation API exposed as script globals
- `TrowserApiServer` -- HTTP REST server bridging LLMs to the automation context
- `TestAssert` -- assertion library with pass/fail tracking
- `NetworkLog` / `ConsoleLog` -- captured traffic and console messages
- `AccessibilityChecker` -- WCAG compliance checker via axe-core
- `ScriptEngine` -- Roslyn integration that runs `.csx` scripts

## Roadmap
I see five different paths to take:
- Rikard's tool (test idea collection, more things that help me)
- API enhancements and competition with Microsoft Playwright/Copilot
- Focus on a specific area, e.g. security testing
- API/Scripting additions, advanced .trw files, Selenium/Playwright import/export
- Unexpected feedback from community

## Third-party enablers

This tool bundles the following open-source libraries:

- retire.js (Apache-2.0)
- axe-core (MPL-2.0)
- html-validate (MIT)
- gremlins.js (MIT)
- web-vitals (Apache-2.0)

Full license texts are included in the `licenses/` folder of the distributable.