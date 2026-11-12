# Trowser API Index

Quick-scan table of contents for all Trowser REST endpoints and MCP tools.
No arguments — just method, path, and one-line purpose.

> **Auto-generated** from `TrowserApiServer*.cs` and `McpHandler.ToolDefinitions.cs` on 2026-11-11.
> Do not edit by hand — run `scripts/generate-api-index.ps1` after API changes.
> Full details: [trowser-api-reference.md](trowser-api-reference.md) · Doc map: [DOCUMENTATION.md](../DOCUMENTATION.md)

**Base URL:** `http://localhost:6923` · **MCP:** `POST http://localhost:6923/mcp`

---

## REST API

### Session Log

| Method | Endpoint | Purpose |
|--------|----------|---------|
| DELETE | `/api/journal` | Remove an entry. Query: `index` (required). The index is never reused; subsequent GET responses include it in `deleted[]… |
| GET | `/api/journal` | Get journal entries (unified session log). |
| PATCH | `/api/journal` | Update an existing journal entry. |
| POST | `/api/journal` | Add a structured entry: { "kind": "bug/enhancement/observation/charter/testing/test-idea/user/note", "note": "title...",… |
| GET | `/api/journal/export` | Generate a formatted test report from the journal. |
| POST | `/api/journal/import` | Import a trowser-journal JSON bundle (entries + pointers). |

### Pointers & Checkpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/checkpoint` | Create a checkpoint bounding "now" (records the current journal index). |
| GET | `/api/checkpoint/{id}` | Fetch a checkpoint with a summary of activity **since** it (GUI actions, errors, pointers). **Gate-free**. |
| GET | `/api/checkpoints` | List checkpoints. **Gate-free**. Returns `{ checkpoints, count, latest }`. |
| POST | `/api/pointer` | Create a pointer. Anchor it with a `ref` (preferred), `selector`, semantic locator fields (`role`+`name`, `testId`, `byT… |
| DELETE | `/api/pointer/{id}` | Remove a pointer by id. |
| GET | `/api/pointer/{id}` | Fetch a single pointer by id. **Gate-free**. |
| POST | `/api/pointer/{id}/resolve` | Re-resolve a pointer's anchor against the current DOM and update its status. |
| GET | `/api/pointers` | List pointers (in-memory, **gate-free**). |

### Decisions

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/decision` | Ask the human to make a call. Blocks only in the `gate` lane. |
| DELETE | `/api/decision/{id}` | Withdraw a pending question the agent no longer needs answered, so it stops asking for attention. |
| GET | `/api/decision/{id}` | Fetch a single decision, wrapped the same way as `POST /api/decision`. |
| POST | `/api/decision/{id}/answer` | Record an answer. Fields: `option` (key or label, **required**), `note` (required for Other — the custom text; use the l… |
| GET | `/api/decisions` | List decisions. Optional filters: `status` (`pending`, `answered`, `defaulted`, `expired`, `cancelled`), `lane`. Returns… |

### Page State & Inspection

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/abort` | Force-cancel the current operation and return server to idle (bypasses gate, works when busy) |
| GET | `/api/assertions` | Current test assertion results |
| POST | `/api/clear-all` | Reset all test state: console, network, cookies, mocks, intercepts, assertions, throttle, viewport, emulation, downloads, trace, storage. |
| POST | `/api/clear-session` | Lighter reset: clears test artifacts (console, network, assertions, mocks, intercepts, throttle, viewport, emulation); p… |
| GET | `/api/console` | Browser console messages |
| POST | `/api/diff-state` | Diff two stored snapshots: { "before": N, "after": M } refGeneration from GET /api/state — elements added/removed, text/… |
| POST | `/api/force-navigate` | Recover frozen page: { "url": "about:blank", "terminateScripts": true } — CDP Runtime.terminateExecution + Page.navigate… |
| GET | `/api/info` | Server and page info |
| GET | `/api/interactive` | All interactive elements with selectors and ref numbers |
| GET | `/api/network` | Network traffic log. Query: ?errors=true, ?url=X, ?method=GET, ?status=404, ?statusRange=500-599, ?type=Script, ?limit=N… |
| GET | `/api/page-text` | All visible page text (document.body.innerText) |
| GET | `/api/ping` | Health check (always responds, even when browser is busy). Returns busy status and current operation. |
| GET | `/api/screenshot` | Capture screenshot. Query params: ?base64=true |
| GET | `/api/source` | Full page HTML source (document.documentElement.outerHTML) |
| GET | `/api/state` | Full page state (URL, title, headings, frames, interactive elements, errors). |
| POST | `/api/state/enrich` | Batch-fetch text/attributes for refs: { "refs": [0,1,2], "fields": ["text","href","type","name","id","class","required",… |
| POST | `/api/state/refresh` | Force full page state rescan after DOM mutations. Returns same data as GET /api/state with refreshed:true |

### Inspiration

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/inspiration` | Get a random testing inspiration message. |

### Notifications

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/message` | Display a message overlay to the human tester (gate-free). Body: { "text", "level": "info/warning/error", "duration" }. |

### Navigation

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/go-back` | Navigate back in history (same as navigate with action back) |
| POST | `/api/go-forward` | Navigate forward in history (same as navigate with action forward) |
| POST | `/api/navigate` | Navigate: { "url": "..." } or session history { "action": "back" / "forward" } (CDP) |
| POST | `/api/settings/scope` | Set navigation scope programmatically: { "scope": "https://*.example.com/*" } (same as Settings / --scope). |
| GET | `/api/settings/throttle` | Get API request pacing: maxRequestsPerSecond, delayBetweenNavigations (0 = off). |
| POST | `/api/settings/throttle` | Set request pacing to reduce WAF/bot blocks: { "maxRequestsPerSecond": 2, "delayBetweenNavigations": 3000 } — min gap be… |
| POST | `/api/wait-for-final-navigation` | Wait for redirect chain to settle: { "quietPeriod": 500, "timeout": 15000 } |
| POST | `/api/wait-for-idle` | Wait for network quiet + no CSS animations: { "quietPeriod": 500, "timeout": 10000 } |
| POST | `/api/wait-for-navigation` | Wait for page navigation: { "timeout": 10000 } |

### Element Interaction

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/click` | Click element: { "ref": N, "frame": "child", "button": "left/right/middle", "clickCount": 1/2 } |
| POST | `/api/find` | Search visible page text: { "text": "...", "caseSensitive": false, "regex": false, "scrollTo": 0, "highlight": true } |
| POST | `/api/find/clear` | Remove find highlights from the page |
| POST | `/api/hover` | Hover over element: { "ref": N } or { "selector": "..." } |
| POST | `/api/key` | Send keyboard key: { "key": "Tab" } or { "key": "Enter", "ref": 5, "modifiers": ["Shift"] } |
| POST | `/api/scroll` | Scroll page/element: { "direction": "down" } or { "ref": N, "scrollIntoView": true } |
| POST | `/api/select` | Select dropdown: { "ref": N, "value": "..." } or { "selector": "...", "value": "..." } |
| POST | `/api/type` | Type into element: { "ref": N, "text": "..." } or { "ref": N, "value": "..." } (value=content alias) or { "selector": ".… |
| POST | `/api/upload` | File input: { "ref": N / selector..., "path": "C:\\\\full\\\\path" / "paths": [...], or "base64" + "fileName", optional… |

### Element Data

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/attribute` | Get element attribute: { "ref": N, "attribute": "..." } |
| POST | `/api/extract` | Extract structured data from repeating elements into JSON array. |
| POST | `/api/extract-text` | Alias for POST /api/text multi-extract (targets / selectors / patterns). |
| POST | `/api/property` | Get element DOM property (live value): { "ref": N, "property": "value" } |
| POST | `/api/text` | Get element text: { "ref": N } or { "selector": "..." }. |

### Script Execution

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/batch` | Execute multiple actions: { "actions": [{"action":"click","ref":5},{"action":"text","ref":3}] } |
| POST | `/api/execute-js` | Execute JavaScript: { "script": "...", "frame": "optional frameId/name", "timeout": 30000 }. |
| POST | `/api/execute-script` | Execute C# test script: { "code": "..." } |
| POST | `/api/test-scenario` | Run a sequence of API calls in-process (one round-trip): { "steps": [{ "method", "path", "query?", "body?", "capture?":… |

### Waiting

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/wait` | Wait for element: { "selector": "...", "timeout": 10000 } |
| POST | `/api/wait-for-network` | Wait for specific network request matching URL substring. |

### Assertions

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/assert/element-attribute` | Assert element attribute: { "ref": N, "attribute": "...", "expected": "..." } |
| POST | `/api/assert/element-contains-text` | Assert element text contains: { "ref": N, "expected": "..." } |
| POST | `/api/assert/element-count` | Assert element count: { "selector": "...", "expected": N } |
| POST | `/api/assert/element-not-visible` | Assert element is not visible: { "ref": N } or { "selector": "..." } |
| POST | `/api/assert/element-text` | Assert element text equals: { "ref": N, "expected": "..." } |
| POST | `/api/assert/element-text-batch` | Assert many element texts in one call: { "assertions": [{ "selector": "#id", "expected": "5", "contains?": false, "messa… |
| POST | `/api/assert/element-visible` | Assert element is visible: { "ref": N } or { "selector": "..." } |
| POST | `/api/assert/page-contains` | Assert page contains text: { "text": "...", "message": "..." } |
| POST | `/api/assert/page-not-contains` | Assert page does not contain text: { "text": "...", "message": "..." } |
| POST | `/api/assert/reset` | Reset all assertion results |
| POST | `/api/assert/title` | Assert page title contains: { "expected": "..." } |
| POST | `/api/assert/url` | Assert URL contains: { "expected": "..." } |

### Dialog Handling

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/dialog` | Get the most recent native dialog (alert/confirm/prompt) |
| POST | `/api/dialog/dismiss` | Clear the last dialog record |
| POST | `/api/dialog/handle` | Configure dialog handling: { "accept": true/false, "promptText": "..." } |

### Cookies

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/cookies` | Get all cookies for current URL. Query params: ?name=sessionId |
| POST | `/api/cookies/clear` | Delete all cookies |
| POST | `/api/cookies/delete` | Delete cookie: { "name": "x", "domain": ".example.com", "path": "/" } |
| POST | `/api/cookies/set` | Set cookie: { "name": "x", "value": "v", "domain": ".example.com", "secure": true, "sameSite": "Lax" } |

### Web Storage

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/storage` | Get storage entries. `?type=local/session/indexeddb` (default: `local`), `?key=<name>` for single value. |
| POST | `/api/storage` | **Alias of [`POST /api/storage/set`]( |
| POST | `/api/storage/clear` | Clear all entries. **Optional:** `type`. Blocked in safe mode. For IndexedDB, optional `database`/`db` filter deletes ma… |
| POST | `/api/storage/delete` | Delete key. **Required:** `key`. **Optional:** `type`. Blocked in safe mode. |
| POST | `/api/storage/set` | Set key/value. **Required:** `key`, `value`. **Optional:** `type` (default: `"local"`). Blocked in safe mode. |

### Viewport (Responsive Testing)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/screen-curtain` | Get screen curtain state: { "enabled": true/false } — black overlay hiding page visuals for blind/screen-reader testing |
| POST | `/api/screen-curtain` | Set or toggle screen curtain: { "enabled": true/false } or { "toggle": true }. Same as Ctrl+B in the GUI. |
| GET | `/api/viewport` | Get current viewport size and available presets |
| POST | `/api/viewport` | Set viewport: { "width": 390, "height": 844 } or { "preset": "SmallPhone" }. |

### Tab Management

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/tabs` | List all open tabs with index, id, title, URL, isActive, and owner (human/agent/shared) |
| POST | `/api/tabs/close` | Close a tab: { "tabIndex": N } (required; "index" accepted as alias) |
| POST | `/api/tabs/new` | Open a new tab: { "url": "...", "owner": "human/agent/shared" }. Agent-owned by default. Switches to the new tab. |
| POST | `/api/tabs/switch` | Switch active tab: { "tabIndex": N } |

### Web MCP (Page-Registered Tools)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/webmcp` | Detect WebMCP tools registered via `navigator.modelContext`. |
| POST | `/api/webmcp/call` | Call a WebMCP tool. **Required:** `tool` (name). **Optional:** `arguments`. |

### Network Mocking (Fault Injection)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/mock` | List active mock rules |
| POST | `/api/mock` | Add mock: { "urlPattern": "*/api/users*", "status": 500, "body": "{...}", "delay": 2000 } |
| POST | `/api/mock/clear` | Clear all mock rules |
| POST | `/api/mock/remove` | Remove mock: { "urlPattern": "*/api/users*" } |

### Network Interception (Request Breakpoints)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/intercept` | List intercept (breakpoint) rules and pending requests |
| POST | `/api/intercept` | Add breakpoint: { "urlPattern": "regex", "method": "GET" } |
| POST | `/api/intercept/abort` | Abort a pending request: { "requestId": 1 } |
| POST | `/api/intercept/clear` | Clear all breakpoints and release pending requests |
| POST | `/api/intercept/continue` | Continue a pending request: { "requestId": 1, "url": "...", "method": "...", "headers": {} } |
| POST | `/api/intercept/fulfill` | Fulfill with custom response: { "requestId": 1, "status": 200, "body": "...", "headers": {} } |
| POST | `/api/intercept/remove` | Remove breakpoint: { "urlPattern": "regex" } |
| POST | `/api/intercept/replay` | Replay a pending request N times concurrently: { "requestId": 1, "concurrency": 10 } |

### Load Testing

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/load-test` | Fire a request N times concurrently: { "url": "...", "method": "GET", "concurrency": 10, "useBrowserCookies": true } |

### Browser Fetch (API Testing)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/fetch` | Send HTTP request from browser context (includes cookies/auth): { "url": "...", "method": "POST", "headers": {}, "body":… |
| POST | `/api/fetch-direct` | **Gate-free server-side fetch** using `HttpClient`. |
| POST | `/api/fetch-raw` | Send HTTP/1.x bytes on a new TCP/TLS connection (not `HttpClient`, not WebView2). |
| POST | `/api/fetch/batch` | Multiple fetch() calls in parallel or sequence: { "requests": [{ "url", "method", "headers", "body"/"json" }], "concurre… |

### Network Throttling

| Method | Endpoint | Purpose |
|--------|----------|---------|
| DELETE | `/api/network/throttle` | Disable throttling (restore full speed). |
| GET | `/api/network/throttle` | Current throttle state and presets. |
| POST | `/api/network/throttle` | Enable throttling. Provide `preset` **or** custom `downloadKbps`+`uploadKbps`+`latencyMs`. |

### Auditing & Analysis

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/accessibility` | Run WCAG audit: { "level": "AA" } |
| POST | `/api/audit-all` | Full page health: accessibility, performance, security (CVE + XSS + mixed content), security/headers, validate-html, SEO… |
| POST | `/api/check-links` | Check links for broken URLs: { "scope": "anchors", "external": true, "timeoutMs": 5000, "concurrency": 10 } |
| POST | `/api/compatibility` | Analyze JavaScript for backward compatibility with older browsers (iOS 15, Android 10) |
| POST | `/api/consistency` | GUI consistency audit: fonts, colors, sizing, spacing |
| POST | `/api/page-text/structured` | Extract structured text: headings, paragraphs, links, buttons, labels, images, word count |
| POST | `/api/performance` | Measure Web Vitals performance: Core Web Vitals, navigation timing, resource summary |
| POST | `/api/quicktest` | Alias for POST /api/audit-all — combined audits in a single round-trip. |
| POST | `/api/seo` | SEO audit: title, meta description, robots, canonical, OG/Twitter tags, hreflang, JSON-LD, h1 count |
| POST | `/api/tab-order` | Verify keyboard tab order (real Tab/Shift+Tab): { "selector": "#main", "expectedOrder": ["Email", "Password"] } |
| POST | `/api/third-party` | Third-party resource inventory: external scripts, stylesheets, iframes, fonts, SRI coverage |
| POST | `/api/validate-html` | Validate HTML markup using html-validate |

### Security Testing

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/security` | Passive security overview (Quicktests → 1 Security Scan modules): tech stack, CVEs, headers, CORS, XSS, cookies, storage… |
| POST | `/api/security/account-enumeration-scan` | REST user-list leak (network-discovered `/api/users` paths + scaffold), login valid/invalid differential (status/length/… |
| POST | `/api/security/api-inventory` | Dedicated API inventory pass (same enrichment as attack-surface + classification). |
| POST | `/api/security/attack-surface` | Auto-generate an attack surface map from **captured network traffic** (endpoints, methods, parameters, auth, response patterns). |
| POST | `/api/security/auth-bypass-pivot` | Captures a token (explicit, session JWT analyze, cookie session, or SQLi login bypass) and retests endpoints that reject… |
| POST | `/api/security/auth-control-identifier` | Identify which cookies, headers, and token fields **actually gate** a captured request. |
| POST | `/api/security/auto-scan` | Automated scan pipeline: runs attack-surface then targeted scanners (SQLi, IDOR, CSRF, path-traversal, SSRF, open-redire… |
| POST | `/api/security/bfla-probe` | **Broken Function Level Authorization** probe: sends **POST/PUT** to admin paths using the **current session** cookies. |
| POST | `/api/security/body-size-limit-scan` | escalating tiers 1 KB → 64 KB → 256 KB → 1 MB (one request per tier) on **POST/PUT/PATCH** endpoints only (GET/HEAD are… |
| POST | `/api/security/brute-force` | Sends **N sequential** failed login attempts (wrong password) to measure **lockout / rate-limit** signals, or **password… |
| POST | `/api/security/cache-deception-scan` | **Web Cache Deception (WCD)** scanner. |
| POST | `/api/security/cache-map` | Cache **identification + key-mapping indication**. |
| POST | `/api/security/cache-poison-scan` | Classic **web cache poisoning** scanner. |
| POST | `/api/security/cache-pollution-scan` | **Live-key error pollution** (first dig-deep once a cache is identified). |
| GET | `/api/security/callbacks` | GET /api/security/callbacks — security callbacks |
| POST | `/api/security/callbacks` | POST /api/security/callbacks — security callbacks |
| POST | `/api/security/captcha-replay-scan` | detects reCAPTCHA/hCaptcha/Turnstile in DOM (`observations[]` with `captcha-present-untestable`), GET JSON captcha/chall… |
| POST | `/api/security/chain-analyze` | POST /api/security/chain-analyze — security chain analyze |
| GET | `/api/security/chain-findings` | GET /api/security/chain-findings — security chain findings |
| POST | `/api/security/chain-findings` | POST /api/security/chain-findings — security chain findings |
| POST | `/api/security/chain-findings/add` | POST /api/security/chain-findings/add — security chain findings add |
| GET | `/api/security/chain-patterns` | GET /api/security/chain-patterns — security chain patterns |
| POST | `/api/security/chain-patterns` | POST /api/security/chain-patterns — security chain patterns |
| POST | `/api/security/chain-prove` | Run a **proof template** for a `patternId`. |
| POST | `/api/security/clickjack-test` | Clickjacking / UI redressing. |
| POST | `/api/security/client-prototype-pollution` | Client-side prototype pollution via URL query/hash and postMessage canaries, then optional gadget→sink escalation. |
| POST | `/api/security/client-surface` | Client-side attack-surface map (browser-native sibling of `/api/security/attack-surface`). |
| POST | `/api/security/cmd-canary` | **Command injection / RCE indicator** canaries on injectable string parameters. |
| POST | `/api/security/cookie-prefix-bypass` | POST /api/security/cookie-prefix-bypass — security cookie prefix bypass |
| POST | `/api/security/cookies` | Cookie security audit: Secure, HttpOnly, SameSite, domain scoping, lifetime |
| POST | `/api/security/cors` | CORS configuration audit. |
| POST | `/api/security/costly-operations` | analyzes captured traffic and optional DOM for operations that can be expensive on one or a few requests (rate limits may not help). |
| POST | `/api/security/crawl-light` | Light same-origin crawler (BFS): follows `<a href>` links and enumerates `<form action>` URLs (GET navigation only — no POST submissions). |
| POST | `/api/security/csrf` | CSRF assessment from the **live page** and **network log**. |
| POST | `/api/security/csti-scan` | **Client-side template injection (CSTI)** scan: navigates the browser with template payloads in URL **query** or **hash*… |
| POST | `/api/security/cswsh-test` | POST /api/security/cswsh-test — security cswsh test |
| POST | `/api/security/default-credential-canary` | Default-credential canary against login forms/URLs (built-in wordlist includes `admin/admin123`, `admin@juice-sh.op/admin123`, and 20+ common defaults). |
| POST | `/api/security/deserialization-scan` | **Deserialization scan** for JSON sinks + fixed paths (`/b2b/v2/orders`, `/api/serialize`, …): baseline → **node-seriali… |
| POST | `/api/security/discover` | Endpoint/directory discovery. |
| POST | `/api/security/dom-flows` | Answer: “where does attacker-controlled data become executable or security-sensitive DOM state?” Builds chains `{source,… |
| POST | `/api/security/dom-xss-audit` | First-class **DOM XSS** pass on the **current page** URL (no network-log sweep). |
| POST | `/api/security/fail-open-scan` | Fail-open probe: strip session cookies and invalid JWT on traffic-derived sensitive endpoints. |
| POST | `/api/security/file-upload-scan` | **File upload validation**: baseline PDF → **200 KB oversize** → **`.exe`** wrong-type → **JPEG/PHP polyglot**; SPA shel… |
| GET | `/api/security/findings` | GET /api/security/findings — security findings |
| POST | `/api/security/firewall-test` | Client-side firewall testing — injects real bypass techniques into the live browser and observes whether CSP, SRI, ifram… |
| POST | `/api/security/forced-error-scan` | Stack-trace / verbose error disclosure probe (malformed JSON POST). |
| POST | `/api/security/gadget-chains` | XS-Leaks-style orchestrator for **client-side gadget chains** (DOM clobbering, client PP, DOM XSS flows): ranks radar hi… |
| POST | `/api/security/gadget-radar` | Runtime **gadget radar**: logs missing-global reads on `window`/`document` (non-perturbing; installed with Ambient runti… |
| POST | `/api/security/graphql-analyze` | GraphQL endpoint security analysis: introspection test, mutation/subscription discovery, query batching, alias amplifica… |
| POST | `/api/security/harvest-ids` | Harvest numeric/GUID/hex IDs from network log + DOM; returns **`suggestedBoundaryTests`** for `authz/boundary`. |
| POST | `/api/security/headers` | Analyze HTTP response headers for security misconfigurations (OWASP) |
| POST | `/api/security/host-header` | Host header injection scanner via **raw TCP HTTP probing**. |
| POST | `/api/security/idor-scan` | Fetches a template with **exactly one** `§id§` or `{{id}}` marker for multiple **id** values; compares **status**, **len… |
| POST | `/api/security/js-audit` | Fetch page script[src] assets and heuristically scan for hardcoded creds, internal URLs, debug/tuning flags (complements source-maps). |
| POST | `/api/security/js-libraries` | Retire.js scan for known vulnerable JavaScript library versions on the current page |
| POST | `/api/security/jwt-acceptance-sweep` | Cookie-isolated sweep for **missing authentication** and **JWT alg:none acceptance** (anonymous GET vs forged alg:none). |
| POST | `/api/security/jwt-analyze` | Reads **cookies, localStorage, and sessionStorage** via one in-page script; finds JWT-shaped strings; Base64url-decodes header/payload (no signing or forgery). |
| POST | `/api/security/jwt-forge` | Pure **JWT (JWS) manipulation** for security testing: decode `baseToken`, apply **`modifications`** to header/payload JS… |
| POST | `/api/security/jwt-header-abuse` | POST /api/security/jwt-header-abuse — security jwt header abuse |
| POST | `/api/security/ldap-scan` | POST /api/security/ldap-scan — security ldap scan |
| POST | `/api/security/llm-chat-interact` | send one prompt through the page chat widget; returns `{ prompt, responseText, responseHtml, inputSelector, responseSelector }`. |
| GET | `/api/security/llm-endpoint-discover` | GET /api/security/llm-endpoint-discover — security llm endpoint discover |
| POST | `/api/security/llm-endpoint-discover` | POST /api/security/llm-endpoint-discover — security llm endpoint discover |
| POST | `/api/security/llm-http-mcp-list` | POST /api/security/llm-http-mcp-list — security llm http mcp list |
| POST | `/api/security/llm-http-send` | POST /api/security/llm-http-send — security llm http send |
| GET | `/api/security/llm-redteam-probes` | lists all probe IDs, category names, and `coverage` metadata (use for `probeIds` / `categories` filters). |
| POST | `/api/security/llm-redteam-scan` | YAML probe corpus (**LLM01–03 + LLM05–07 + LLM09**; see `coverage` in response), plus optional **RAG/memory poison** (LL… |
| POST | `/api/security/llm-sink-assist` | POST /api/security/llm-sink-assist — security llm sink assist |
| POST | `/api/security/logout-invalidation-probe` | perform logout, replay protected URL with pre-logout cookie; flags **`SESSION_STILL_VALID`** only when the **logout step succeeded** (2xx/3xx — not 404/405). |
| POST | `/api/security/mass-assignment-patch` | **PATCH/PUT self-promote** mass-assignment probe (OWASP WSTG-INPV-20 / API mass-assignment): discovers profile update en… |
| POST | `/api/security/mass-assignment-register` | **Registration mass-assignment** scaffold: probes signup/register paths with extra privileged fields. |
| POST | `/api/security/mass-assignment-scan` | Mass-assignment probe: re-sends a JSON or form-urlencoded body with privileged fields and checks whether the value is echoed or newly persisted. |
| POST | `/api/security/methods` | Test which HTTP methods are allowed on a URL. |
| POST | `/api/security/missing-parameter-scan` | Omit each top-level JSON field on traffic-derived POST bodies; flags 500+stack traces and NPE field hints. |
| POST | `/api/security/mixed-content` | Mixed content audit: detect HTTP resources on HTTPS pages (scripts, images, stylesheets) |
| POST | `/api/security/nextjs-rsc-scan` | **Next.js RSC / Flight deserialization** probe (CVE-2025-66478 class): fingerprint App Router → enumerate action hashes → Flight canary payloads. |
| POST | `/api/security/nosql-scan` | POST /api/security/nosql-scan — security nosql scan |
| POST | `/api/security/nuclei-scan` | Native runner over a **curated embedded subset** of [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT), plus **your own templates**. |
| GET | `/api/security/nuclei-templates` | Inventory the runnable nuclei templates (embedded subset and/or a user `templatesDir`) **without scanning**, so you can… |
| POST | `/api/security/oauth-flow-test` | OAuth2/OIDC authorization-flow testing: passive analysis of captured authorize/callback traffic (state, PKCE, fragment t… |
| POST | `/api/security/oidc-analyze` | OIDC provider security analysis: fetches .well-known/openid-configuration, flags dangerous grant types (implicit, passwo… |
| POST | `/api/security/open-redirect-scan` | Open redirect scanner (CWE-601): probes redirect/url/next parameters with external URLs using redirect:manual and checks Location header for off-site redirects. |
| POST | `/api/security/openapi-smoke` | POST /api/security/openapi-smoke — security openapi smoke |
| POST | `/api/security/osv-check` | OSV enrichment for a raw manifest body (JSON, lockfile, requirements.txt, etc.) without web fetch. |
| POST | `/api/security/parser-probe` | **Parser differential** probe for JSON **POST/PUT/PATCH** endpoints: runs a **Content-Type matrix** (XML, form-urlencode… |
| POST | `/api/security/password-reset-weak-scan` | Weak **security-question password reset** — fetch question, try canonical answers, optionally change password. |
| POST | `/api/security/path-filter-bypass` | NUL-byte, double-encoding, and backslash-normalization bypass probes on directory bases. |
| POST | `/api/security/path-traversal` | Path traversal probes on GET query params (network log or explicit urls). Requires safetyMode: active |
| POST | `/api/security/postmessage` | Enumerate `message` listeners (runtime sensor + CDP), grade origin checks (`none` / `weak` / `strict` / `unknown`), **sc… |
| POST | `/api/security/prototype-pollution-scan` | **Server-side prototype pollution**: POST JSON with **`__proto__`** and **`constructor.prototype`** pollution keys, then… |
| POST | `/api/security/race-condition-scan` | discovers single-use POST endpoints from traffic (submit, redeem, vote, confirm, …), refreshes CSRF from the current pag… |
| POST | `/api/security/rate-limit-audit` | discovers login, OTP, search, export, coupon, and write API endpoints from traffic; runs sequential baseline (default 5)… |
| POST | `/api/security/redos-scan` | evil-regex payloads per injectable search/filter/email parameter (max 3, sequential). |
| POST | `/api/security/reset-token` | POST /api/security/reset-token — security reset token |
| POST | `/api/security/response-field-diff` | **Excessive data exposure** probe: compares JSON field paths between **two captured identities** on the same endpoints. |
| POST | `/api/security/rest-scaffold` | Probes common REST collection paths (`/api/Users`, `/rest/admin/…`, etc.) without authentication. |
| GET | `/api/security/saml-capture` | GET /api/security/saml-capture — security saml capture |
| POST | `/api/security/saml-capture` | Capture SAML assertions during SSO login flows. |
| POST | `/api/security/saml-decode` | Decode SAML messages from the network log or raw input. |
| POST | `/api/security/saml-replay` | Replay a captured SAML assertion with modifications for security testing. |
| POST | `/api/security/secrets-harvest` | Unified secret/credential harvesting: JS bundles, cookies, storage, network responses, network request headers (Bearer t… |
| POST | `/api/security/service-worker-audit` | Browser-native **service worker** review on the **current origin** (callable without running client-surface first). |
| POST | `/api/security/session-fixation-scan` | Detects **session fixation** — captures **all** cookies before login, authenticates, flags unchanged **session-like** co… |
| POST | `/api/security/session-id` | Session identifier strength analysis. |
| GET | `/api/security/shadow` | GET /api/security/shadow — security shadow |
| POST | `/api/security/shadow` | POST /api/security/shadow — security shadow |
| POST | `/api/security/shadow/clear` | Clear accumulated findings. Optional: `{ "category": "headers" }`. |
| POST | `/api/security/smuggling` | HTTP Request Smuggling via raw TCP: confirmed = repeated differential 404 (CL.TE/TE.CL canary); everything else is informational. |
| POST | `/api/security/source-maps` | Source map & debug mode audit: sourceMappingURL refs, accessible .map files, Angular/React/Vue debug indicators |
| POST | `/api/security/sqli-login-sweep` | POST /api/security/sqli-login-sweep — security sqli login sweep |
| POST | `/api/security/sqli-scan` | SQL injection probe with **unified findings**. |
| POST | `/api/security/sse-audit` | POST /api/security/sse-audit — security sse audit |
| POST | `/api/security/ssrf-orchestrator` | SSRF orchestrator: scaffold paths + ssrf-scan + open-redirect escalation + jwt-header-abuse + callback poll + chain-analyze. |
| POST | `/api/security/ssrf-scan` | SSRF scanner: injects internal IPs, cloud metadata URLs, protocol handlers, and callback probe URLs into URL-like parame… |
| POST | `/api/security/ssti-polyglot-scan` | **Fast reflected SSTI** probe: single GET **polyglot** payload `${7*7}{{7*7}}<%=7*7%> |
| POST | `/api/security/ssti-scan` | SSTI scan with **unified findings**. |
| POST | `/api/security/ssti-stored-scan` | **Stored SSTI**: POST template payload to profile-shaped fields (`bio`, `about`, `signature`, …), then **GET readback**… |
| POST | `/api/security/storage` | Web storage security audit: tokens, PII, JWTs, HTML/XSS risk in localStorage/sessionStorage |
| POST | `/api/security/subdomain-takeover` | POST /api/security/subdomain-takeover — security subdomain takeover |
| POST | `/api/security/supply-chain-scan` | Supply chain scan: Retire.js, third-party/SRI, manifest fetch + OSV.dev, CI/CD exposure, JS bundle fingerprinting, Retir… |
| POST | `/api/security/swaggering` | discover OpenAPI/Swagger (traffic + well-known paths), build an operation catalog, run **session-authenticated** probes… |
| POST | `/api/security/tech-stack` | Tech stack fingerprinting: servers, frameworks, JS libraries, WAFs, CDNs, CMSes from headers, cookies, DOM, and script analysis. |
| POST | `/api/security/tls-introspection` | POST /api/security/tls-introspection — security tls introspection |
| POST | `/api/security/token-entropy` | POST /api/security/token-entropy — security token entropy |
| POST | `/api/security/trace-input` | Input→Network→DOM causality tracing. |
| POST | `/api/security/trusted-header-bypass` | Trusted-proxy header bypass: anonymous GET on 401/403 paths with `X-Forwarded-User`, `X-Real-IP`, etc. |
| POST | `/api/security/verify` | Exploit verifier — proves a vulnerability by **inject** (optional browser `fetch`), **navigate** to render page, **evalu… |
| POST | `/api/security/verify-workflow` | `setup` → `trigger` → `oracle` → `cleanup`. Oracle verdict is deterministic (machine decides pass/fail). |
| POST | `/api/security/verify/batch` | Same verification flow as `/api/security/verify`, **sequentially**, in one **shared browser session** (cookies/login pre… |
| POST | `/api/security/waf-bypass` | WAF bypass technique probe. |
| POST | `/api/security/websocket-audit` | POST /api/security/websocket-audit — security websocket audit |
| POST | `/api/security/websocket-authz` | POST /api/security/websocket-authz — security websocket authz |
| POST | `/api/security/websocket-fuzz` | POST /api/security/websocket-fuzz — security websocket fuzz |
| POST | `/api/security/workflow-skip-scan` | infers late-stage POST endpoints from traffic (confirm, complete, submit, redeem, …). |
| POST | `/api/security/xs-leaks` | Cross-site leak differential scanner. |
| POST | `/api/security/xss` | DOM XSS audit: inline handlers, javascript: URLs, dangerous sinks, cross-domain scripts |
| POST | `/api/security/xss-dom-audit` | POST /api/security/xss-dom-audit — security xss dom audit |
| POST | `/api/security/xss-scan` | Active XSS scan with **unified findings**. |
| POST | `/api/security/xssi-scan` | Cross-Site Script Inclusion (XSSI) and **JSONP exposure** assessment from the **network log** plus optional explicit URLs. |

### Robustness Testing

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/fuzz` | Browser-context request fuzzer (Intruder-style). |
| GET | `/api/fuzz/payloads` | List built-in payload sets with sample payloads and counts. |
| POST | `/api/interrupter` | Run TrowserInterrupter fault-injection test: auto-discovers APIs (including form POSTs), injects faults, reloads, checks… |
| POST | `/api/monkey-test` | Run monkey testing for robustness (gremlins.js). Requires safetyMode: active — may trigger server-side actions. |
| POST | `/api/monkey-trowser` | Run Monkey Trowser smart robustness test. |

### Peer Management (Cross-Instance Testing)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| DELETE | `/api/peer/{name}` | Remove a registered peer Trowser instance |
| POST | `/api/peer/fetch` | **The workhorse for cross-identity testing.** Send an HTTP request through a peer's browser session — the request uses t… |
| POST | `/api/peer/identity/apply` | POST /api/peer/identity/apply — peer identity apply |
| POST | `/api/peer/navigate` | Navigate a peer to a URL (calls `POST /api/navigate` on the peer). |
| POST | `/api/peer/register` | Register a peer Trowser instance. Validates that `baseUrl` is localhost and pings the peer. |
| POST | `/api/peer/screenshot` | Take a screenshot of a peer's current page. |
| POST | `/api/peer/spawn` | Launch another Trowser on localhost and register it (replaces manual `Start-Process` + `peer/register` for scripts). |
| POST | `/api/peer/state` | Gate-free **`GET /api/info`** from a peer (current URL, title, session). |
| POST | `/api/peer/stop` | Stop a spawned peer process and optionally unregister it. |
| GET | `/api/peers` | List all registered peers with health status and session names. |

### Authorization Testing

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/authz/boundary` | **Authorization boundary testing.** Tests a URL with authorized vs unauthorized parameter values and auto-detects when unauthorized access is granted. |
| POST | `/api/authz/coverage` | **BAC coverage report** for one host. |
| POST | `/api/authz/diff` | **Cross-identity authorization comparison.** Runs the same set of endpoints on both the local session AND a registered p… |
| POST | `/api/authz/fuzz` | **Parameter fuzzing with crash detection.** Takes a URL template with `{param}` placeholders and an array of parameter sets. |
| GET | `/api/authz/model` | **Access model.** Read declared intent and identities for one host. |
| PUT | `/api/authz/model` | **Access model.** Set per-resource intent and identities for one host. |
| POST | `/api/authz/probe` | **Batch authorization boundary scanner.** Test whether the current session has access to a list of endpoints in a single call. |
| POST | `/api/authz/role-matrix` | **Authorization role matrix**: fetches endpoints as each captured identity and classifies access (`allowed`, `denied`, `error`, `same-as-admin`). |
| POST | `/api/authz/shadow` | **Live Authz Shadow.** Watches browsing on this instance and replays successful Document/XHR/Fetch requests, plus JSON a… |

### Portable Identity

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/identities` | GET /api/identities — identities |
| GET | `/api/identity` | GET /api/identity — identity |
| POST | `/api/identity/apply` | POST /api/identity/apply — identity apply |
| POST | `/api/identity/capture` | POST /api/identity/capture — identity capture |
| GET | `/api/identity/handoff` | GET /api/identity/handoff — identity handoff |
| POST | `/api/identity/handoff` | POST /api/identity/handoff — identity handoff |
| GET | `/api/session/identity` | GET /api/session/identity — session identity |

### Security Orchestration (Playbooks)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/orchestrate/{id}` | Run a security playbook: { "scope": { "host": "..." }, "safetyMode": "safe", "depth": "standard", "format": "vpx-compact… |
| POST | `/api/orchestrate/dry-run/{id}` | Preview playbook steps without executing: { "safetyMode": "safe", "depth": "standard" } |
| GET | `/api/orchestrate/playbooks` | List all available security playbooks (id, title, category, endpoint) |
| GET | `/api/orchestrate/runs/{runId}` | Poll an async playbook run started with POST /api/orchestrate/{id} and "async": true (gate-free) |

### VPX (Vulnerability Proof Exchange)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/vpx/clear` | Clear in-session VPX state (imported documents, merged findings queue, and related session artifacts). |
| GET | `/api/vpx/export` | Export session findings as a **VPX 1.1** document (Vulnerability Proof eXchange). |
| POST | `/api/vpx/import` | Import a VPX 1.1 document into the session (VPX 1.0 is also accepted) — registers findings for proof queue (`source: vpx… |
| POST | `/api/vpx/render` | Re-render a VPX document: { "vpx": { ... }, "format": "markdown" } |

### Client TLS Certificates

| Method | Endpoint | Purpose |
|--------|----------|---------|
| DELETE | `/api/ssl/certificates` | Remove a client certificate: { "alias": "my-cert" } |
| GET | `/api/ssl/certificates` | List all loaded client certificates (alias, subject, thumbprint, expiry, active status) |
| POST | `/api/ssl/certificates` | Add a client certificate: { "filePath": "path/to/cert.pfx", "password": "...", "alias": "my-cert" } |
| GET | `/api/ssl/certificates/active` | Get the currently active client certificate |
| POST | `/api/ssl/certificates/active` | Set the active client certificate: { "alias": "my-cert" }. Pass null/empty alias to clear. |

### WebSocket

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/websocket/close` | POST /api/websocket/close — websocket close |
| GET | `/api/websocket/connections` | GET /api/websocket/connections — websocket connections |
| GET | `/api/websocket/messages` | GET /api/websocket/messages — websocket messages |
| POST | `/api/websocket/send` | POST /api/websocket/send — websocket send |

### Shadows (Ambient UI)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/shadows` | GET /api/shadows — shadows |
| POST | `/api/shadows` | POST /api/shadows — shadows |

### Utilities

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/scripting-help` | Curated C# scripting (.csx) cheat sheet for LLMs/agents. |
| GET | `/api/test-data` | Get a random test data string or security payload. |

### Other

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/attack-form` | Adaptive form attack ('Attack this form'): inspects the live page to discover the editable fields wired to a form/submit… |
| POST | `/api/click-at` | CDP click at viewport x/y (CSS px); hits painted targets including cross-origin iframes |
| POST | `/api/console/clear` | Clear console log |
| GET | `/api/coverage` | Reflective coverage lens derived from the journal: pages visited, interactive elements exercised, and which quality characteristics have been touched. |
| GET | `/api/downloads` | List captured downloads (id, url, suggestedFileName, path, state, bytes, mime) |
| POST | `/api/downloads/assert` | Assert download: { "fileNameContains", "mime", "minBytes", "exists" } |
| POST | `/api/downloads/clear` | Clear download log: { "deleteFiles": false } |
| POST | `/api/downloads/wait` | Wait until download completed + file on disk: { "fileNameContains": "report", "timeout": 30000, "afterId": 0 } |
| POST | `/api/drag` | Drag: { "from": {"ref":N}, "to": {"selector":"#dst"}, "steps": 10, "frame": "optional" } |
| DELETE | `/api/emulation` | Clear all environment overrides |
| GET | `/api/emulation` | Get environment overrides (geolocation, locale, timezone, colorScheme, reducedMotion, userAgent, permissions) |
| POST | `/api/emulation` | Set environment overrides: { "geolocation": {"latitude":59.3,"longitude":18.0}, "locale": "sv-SE", "timezone": "Europe/S… |
| GET | `/api/frames` | List iframes: frameId, name, url, sameOrigin, parentFrameId |
| GET | `/api/laws` | List loaded Laws and compile diagnostics (`laws[]`, `diagnostics[]`). |
| POST | `/api/laws/add` | Append Law source to `Documents\Trowser Quicktests\Laws\{fileName}` (default `custom.csx`) and reload. |
| POST | `/api/laws/author` | Natural language → Law source with compile/refine loop (uses configured LLM when available). |
| POST | `/api/laws/check` | Run Laws on the UI thread: `{ "nameFilter?", "allLoaded": true, "includeTraffic": false }` → `{ "passed", "failed", "res… |
| POST | `/api/laws/delete` | Delete a user Law file: `{ "fileName" }` or `{ "path" }`. |
| GET | `/api/laws/proposals` | GET /api/laws/proposals — laws proposals |
| POST | `/api/laws/proposals/accept` | POST /api/laws/proposals/accept — laws proposals accept |
| POST | `/api/laws/proposals/reject` | POST /api/laws/proposals/reject — laws proposals reject |
| POST | `/api/laws/replace` | Overwrite a user Law file: `{ "fileName", "code" }` → `{ "valid", "path", "errors?" }`. |
| POST | `/api/laws/validate` | Body: `{ "code": "<Law .csx C |
| GET | `/api/network/{id}` | One captured network entry by id, with request/response headers and any captured body. |
| POST | `/api/network/clear` | Clear network log |
| GET | `/api/network/har` | Export network log as HAR 1.2 JSON. Query: ?includeBody=true, ?url=, ?method=, ?errors=true, ?page=true, ?path=file |
| GET | `/api/page-text/all` | All text nodes including hidden/off-screen + shadow DOM; one line per text node |
| GET | `/api/page-text/screen-reader` | Screen reader strings: alt, aria-label, aria-labelledby/by, title, SVG title/desc + shadow |
| POST | `/api/race-lab/baseline` | Same body shape as synchronize. One sequential soft pass per expanded request. Returns `baseline[]` timeline entries. |
| GET | `/api/race-lab/profiles` | Lists built-in presets (`Hammer`, `Spike`, `Sequential`, `Random`) plus user-saved profiles from `%APPDATA%\\Trowser\\ra… |
| POST | `/api/race-lab/profiles` | Save a user profile (`name`, `requests[]`, `parameters`). Built-in names cannot be overwritten. |
| POST | `/api/race-lab/profiles/export` | Body: optional `names[]`. Returns `{ format, json }` export payload. |
| POST | `/api/race-lab/profiles/import` | Body: `json` (export payload). Merges imported user profiles. |
| POST | `/api/race-lab/run` | **Safety gate:** `"safetyMode": "active"`. |
| POST | `/api/race-lab/synchronize` | Body: **`profile`** `{ name, requests[], parameters }` **or** the same fields at the **top level** (`requests[]`, optional `parameters`). |
| POST | `/api/record/start` | Start interaction recording to a temp .csx (human DOM actions). 409 if already recording. |
| GET | `/api/record/status` | Recording status: { recording, startUrl, startedAt, actionCount } |
| POST | `/api/record/stop` | Stop recording: { description?, toJournal?, path? }. |
| POST | `/api/resource/compare` | Compare a saved baseline to current page after your own actions. |
| POST | `/api/resource/probe` | Resource leak probe: baseline → repeat actions or reloads → GC → compare. |
| POST | `/api/resource/snapshot` | Resource snapshot: JS heap, DOM nodes, event listeners, open WebSockets (CDP). |
| POST | `/api/screenshot/compare` | Compare two screenshots pixel-by-pixel for visual regression testing. |
| GET | `/api/session-memory` | Volatile session memory for the built-in AI Assistant (focus, tasks, last compact handoff). **Gate-free**. |
| POST | `/api/session-memory` | Update session memory. Body: `{ "action": "get"/"set_focus"/"add_task"/"update_task", ... }`. **Gate-free**. |
| GET | `/api/session/cookie-header` | **Gate-free** cookie header material for an absolute `url` query parameter. |
| POST | `/api/shadow/check` | Run **Shadow Heavy** now on the UI thread: all page-fact Laws — `OnPage`, plus `OnAction` and `OnTimer` Laws, which run… |
| GET | `/api/sse/connections` | GET /api/sse/connections — sse connections |
| GET | `/api/sse/messages` | GET /api/sse/messages — sse messages |
| POST | `/api/surpriseme` | Run a random non-destructive quicktest from the embedded catalog. Returns quicktest name and assertion summary. |
| GET | `/api/trace` | Get action timeline steps |
| GET | `/api/trace/export` | Export action timeline JSON |
| POST | `/api/trace/start` | Start action timeline: { "domSnapshots": false, "maxSteps": 200 } |
| POST | `/api/trace/stop` | Stop action timeline recording |
| POST | `/mcp` | MCP Streamable HTTP — JSON-RPC 2.0 (GET/DELETE → 405; empty POST → 202) |

### Repro & Verification

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/repro/capture` | Build a .trw from journal actions since a checkpoint: { "checkpointId", "name", "path", "oracle" }. |
| POST | `/api/repro/verify` | Replay a .trw / bundle / workflow k times: { "trwPath"/"bundlePath"/"workflow", "runs": 3, "clearSession": true, "identity", "expect", "safetyMode": "active" }. |

### Header Overrides

| Method | Endpoint | Purpose |
|--------|----------|---------|
| DELETE | `/api/header-overrides` | Clear all session header overrides. Blocked in `--safe`. |
| GET | `/api/header-overrides` | List session header overrides. |
| PUT | `/api/header-overrides` | Replace the override list: `{ "headers": [{ "name": "User-Agent", "value": "…", "enabled": true }] }`. |

---

## MCP Tools

| Tool | REST equivalent | Purpose |
|------|-----------------|---------|
| `browser_abort` | POST /api/abort | Cancel the in-flight gated operation (long scan, navigation, etc.). Bypasses the gate. REST: POST /api/abort. |
| `browser_accessibility` | POST /api/accessibility | Run a WCAG accessibility audit using axe-core. |
| `browser_assert_download` | POST /api/downloads/assert | Assert a captured download is completed with expected filename/mime/minBytes/file exists. Records into /api/assertions. |
| `browser_assert_element` | POST /api/assert/* | Assert one of: visible, hasText, containsText, attribute(+expected), or count. Target with ref (preferred) or locator. |
| `browser_assert_text` | POST /api/assert/page-contains | Assert that the page contains (or does not contain) specific text. Results are tracked in an assertion summary. |
| `browser_assert_title` | POST /api/assert/title | Assert that the current page title contains the expected value (case-insensitive). |
| `browser_assert_url` | POST /api/assert/url | Assert that the current URL contains the expected substring. |
| `browser_attack_form` | POST /api/attack-form | Probe a live form for client-side validation gaps (type-aware payloads; default does not submit). |
| `browser_attack_surface` | POST /api/security/attack-surface | Map attack surface from network traffic (endpoints, methods, params, auth) with optional OpenAPI/JS enrichment, |
| `browser_audit_all` | POST /api/audit-all | Full page health audit in one call (a11y, Web Vitals, security, headers, HTML, SEO, compatibility, links, consistency, s… |
| `browser_authz_boundary` | POST /api/authz/boundary | Authorization boundary testing. |
| `browser_authz_coverage` | POST /api/authz/coverage | Build a BAC (Broken Access Control) coverage report for a host: cross-references the access model |
| `browser_authz_diff` | POST /api/authz/diff | Cross-identity authorization comparison. |
| `browser_authz_fuzz` | POST /api/authz/fuzz | Parameter fuzzing with crash detection. |
| `browser_authz_model` | GET/PUT /api/authz/model | Get or set the persisted access model for a host: per-(method,urlTemplate) declared sensitivity/ownership |
| `browser_authz_probe` | POST /api/authz/probe | Batch authorization boundary scanner. |
| `browser_authz_role_matrix` | POST /api/authz/role-matrix | Authorization role matrix: fetches endpoints as each captured identity and classifies access (allowed/denied/error). |
| `browser_authz_shadow` | POST /api/authz/shadow | Control the Live Authz Shadow: watches normal browsing and replays authz-relevant requests through registered peers. |
| `browser_check_links` | POST /api/check-links | Check all links on the current page for broken URLs, redirects, and errors. |
| `browser_checkpoint` | POST /api/checkpoint | Mark a sync point in the session. A checkpoint bounds 'what has happened since we last synced' — it records the |
| `browser_clear_all` | POST /api/clear-all | Reset all test session state in one call. Clears: console log, network log, cookies, |
| `browser_clear_session` | POST /api/clear-session | Lighter reset — clears test artifacts (console, network, assertions, mocks, intercepts, |
| `browser_click` | POST /api/click | Click an element (ref preferred, or selector/semantic locator). Auto-waits on navigation links. |
| `browser_click_at` | POST /api/click-at | CDP click at viewport x/y (CSS pixels). Hits the topmost painted target, including cross-origin iframe |
| `browser_client_surface` | POST /api/security/client-surface | Client-side attack-surface map: sources, sinks, message listeners, tabnabbing links, clobber candidates, service workers… |
| `browser_close_tab` | POST /api/tabs/close | Close a browser tab by index. If no index is given, closes the active tab. |
| `browser_compact` | (built-in Chat only) | Compact the built-in assistant conversation context. Call after journaling a completed test segment. |
| `browser_compatibility` | POST /api/compatibility | Analyze the page's JavaScript for backward compatibility with older browsers. |
| `browser_consistency` | POST /api/consistency | Audit the page's visual consistency. Analyzes computed styles to count distinct |
| `browser_console` | GET /api/console | Get browser console messages (logs, warnings, errors). Optional tabIndex reads another tab without switching. |
| `browser_console_clear` | POST /api/console/clear | Clear all captured console messages. Use between test sections to isolate errors |
| `browser_coverage` | GET /api/coverage | Get the reflective coverage lens (REST equivalent: GET /api/coverage): pages visited, interactive |
| `browser_decide` | POST /api/decision | Ask the human tester to make a call, as 2-6 lettered options they answer with one click in the AI Assistant panel. |
| `browser_decisions` | GET /api/decisions | Read the decisions you have asked the human for, and their answers. With no arguments, lists them all with status |
| `browser_dialog` | GET /api/dialog | Get the most recent native dialog (alert, confirm, prompt) that appeared. |
| `browser_diff_state` | POST /api/diff-state | Compare two stored page snapshots by refGeneration (from browser_snapshot / GET /api/state). |
| `browser_dom_flows` | POST /api/security/dom-flows | Show every point where attacker-controlled data becomes executable or security-sensitive DOM state. |
| `browser_dom_xss_audit` | POST /api/security/dom-xss-audit | Active DOM XSS on the **current page** URL. Default depth=standard (medium): passive XSS + dom-flow probe + |
| `browser_downloads` | GET /api/downloads | List captured browser downloads (id, url, suggestedFileName, path, state, bytes, mime). |
| `browser_drag` | POST /api/drag | Drag from one element to another (HTML5 DragEvent when draggable, else CDP mouse; html5 true/false to force). |
| `browser_emulation` | GET /api/emulation | Get or set environment overrides (geolocation, locale, timezone, colorScheme, reducedMotion, userAgent, permissions). |
| `browser_execute_js` | POST /api/execute-js | Run JavaScript in the page and return the string result (awaits Promises; multi-statement auto-IIFE). |
| `browser_extract` | POST /api/extract | Extract structured data from repeating elements (table auto, field map, or simple text list). |
| `browser_fetch` | POST /api/fetch | HTTP from browser context (cookies/session). Prefer over execute-js fetch. json auto-sets Content-Type; |
| `browser_fetch_batch` | POST /api/fetch/batch | Run multiple fetch() requests in the browser context (cookies, session, CORS). |
| `browser_fetch_raw` | POST /api/fetch-raw | Send HTTP/1.x bytes on a new TCP/TLS connection. headers is a raw block string so |
| `browser_find` | POST /api/find | Search visible page text (query or regex). Returns matches with context/selector/bounds; optional scrollTo/highlight. |
| `browser_find_clear` | POST /api/find/clear | Remove all text search highlights previously added by browser_find with highlight=true. |
| `browser_firewall_test` | POST /api/security/firewall-test | Live-verify client defenses (CSP, SRI, iframe sandbox, Permissions-Policy) by injecting bypass techniques — not static header analysis. |
| `browser_force_navigate` | POST /api/force-navigate | Recover from a frozen page (infinite loop, DoS script, resource exhaustion) when normal navigation and MCP are stuck. |
| `browser_fuzz` | POST /api/fuzz | Browser-context request fuzzer (Intruder-style): §MARKER§/{{MARKER}} templates, payload sets, |
| `browser_gadget_radar` | POST /api/security/gadget-radar | Runtime gadget radar: missing-global reads (Shadow-safe) and optional perturbing proto-read traps. |
| `browser_go_back` | POST /api/go-back | Navigate back in browser history. Fails if there is no history to go back to. |
| `browser_go_forward` | POST /api/go-forward | Navigate forward in browser history. Fails if there is no history to go forward to. |
| `browser_handle_dialog` | POST /api/dialog/handle | Configure how native browser dialogs (alert, confirm, prompt) are handled. |
| `browser_header_overrides` | GET /api/header-overrides | Session header overrides for WebView2 browsing (replace if present, add if missing). |
| `browser_hover` | POST /api/hover | Hover over an element (tooltips/menus). Target with ref (preferred) or selector/semantic locator. |
| `browser_identities` | GET /api/identities | List captured identity snapshots (metadata only). REST: GET /api/identities. |
| `browser_identity_apply` | POST /api/identity/apply | Apply captured identity to self or peer. |
| `browser_identity_capture` | POST /api/identity/capture | Capture portable identity snapshot (cookies, storage, optional auth headers). |
| `browser_identity_handoff` | GET/POST /api/identity/handoff | SSO/MFA handoff: action=start waits for human login; action=status polls; action=cancel aborts. |
| `browser_inspiration` | GET /api/inspiration | Get a random testing inspiration message — a creative prompt, heuristic, or lateral-thinking trigger |
| `browser_intercept` | POST /api/intercept | Manage network breakpoints (pause/continue/fulfill/abort held requests). |
| `browser_interrupter` | POST /api/interrupter | Fault-injection: discover/rank APIs from network log, mock faults, reload, check failures. |
| `browser_journal_add` | POST /api/journal | Add a structured entry to the test journal (the session log / notes — there is no separate |
| `browser_journal_delete` | DELETE /api/journal | Delete a journal entry by index. |
| `browser_journal_export` | GET /api/journal/export | Generate a formatted test report (HTML, Markdown, or JSON) from all journal entries. |
| `browser_journal_get` | GET /api/journal | Get test journal entries — the unified timeline of all session activity including actions, notes, |
| `browser_journal_import` | POST /api/journal/import | Import a previously exported journal JSON bundle (entries plus attached pointers). |
| `browser_journal_update` | PATCH /api/journal | Update an existing journal entry by index (from browser_journal_get). Partial: only supplied fields change. |
| `browser_laws` | GET /api/laws | Declare and manage Trowser Laws (.csx invariants: Site/Law/OnPage/Expect). |
| `browser_mixed_content` | POST /api/security/mixed-content | Check for mixed content on the current HTTPS page \u2014 HTTP resources that may be blocked by browsers. |
| `browser_mock` | POST /api/mock | Manage network mock rules (fault injection without hitting the server). |
| `browser_monkey_test` | POST /api/monkey-test | Run a monkey test (gremlins.js) that performs random user actions to test page robustness. |
| `browser_monkey_trowser` | POST /api/monkey-trowser | Monkey Trowser: systematic robustness — click interactives, fuzz forms, crawl in-scope links with attribution. |
| `browser_navigate` | POST /api/navigate | Navigate to a URL, or move backward/forward in session history (Chrome DevTools Page.navigateToHistoryEntry — |
| `browser_network` | GET /api/network | Network traffic log with filters (url/method/status/type/id). summary:true for compact all-matching view; |
| `browser_network_clear` | POST /api/network/clear | Clear the network traffic log. Call this after reviewing network data to free memory, |
| `browser_network_har` | GET /api/network/har | Export the network log as HAR 1.2 JSON (from the in-memory NetworkLog). |
| `browser_network_throttle` | GET /api/network/throttle | Simulate slow network conditions (2G, 3G, 4G, offline) for performance testing. |
| `browser_new_tab` | POST /api/tabs/new | Open a new browser tab. Optionally navigate it to a URL. |
| `browser_orchestrate_dry_run` | POST /api/orchestrate/dry-run/{id} | Dry-run a playbook: playbookId required; same body fields as REST POST /api/orchestrate/dry-run/{id}. |
| `browser_orchestrate_list` | GET /api/orchestrate/playbooks | List security orchestration playbooks (gate-free read). REST: GET /api/orchestrate/playbooks. |
| `browser_orchestrate_run` | POST /api/orchestrate/{id} | Run a security playbook. |
| `browser_page_source` | GET /api/source | Get the full HTML source of the current page (document.documentElement.outerHTML). |
| `browser_page_text` | GET /api/page-text | Get all visible text on the page (document.body.innerText). Useful for searching or verifying page content. |
| `browser_page_text_all` | GET /api/page-text/all | Get all text on the page including hidden/off-screen content (every text node; one line per non-empty segment). |
| `browser_page_text_screen_reader` | GET /api/page-text/screen-reader | Get screen-reader-oriented strings: alt, aria-label, resolved aria-labelledby and aria-describedby, title, |
| `browser_peer_fetch` | POST /api/peer/fetch | Send an HTTP request through a peer Trowser instance's browser session. |
| `browser_peer_navigate` | POST /api/peer/navigate | Navigate a peer Trowser instance to a URL. |
| `browser_peer_register` | POST /api/peer/register | Register a peer Trowser instance for cross-instance security testing (N-body authz). |
| `browser_peer_screenshot` | POST /api/peer/screenshot | Take a screenshot of a peer Trowser instance's current page. |
| `browser_peer_state` | POST /api/peer/state | Get the current page state (URL, title, elements) from a peer Trowser instance. |
| `browser_peer_unregister` | DELETE /api/peer/{name} | Remove a peer Trowser instance from the registry. |
| `browser_peers` | GET /api/peers | List all registered peer Trowser instances with health status and session names. |
| `browser_performance` | POST /api/performance | Measure Web Vitals performance metrics for the current page. |
| `browser_ping` | GET /api/ping | Health check: alive, API port, whether a browser operation is in progress. Bypasses the gate. REST: GET /api/ping. |
| `browser_point` | POST /api/pointer | Point at something for the human (agent→human handoff). A pointer is 'this, here, at this moment, and why': |
| `browser_pointers` | GET /api/pointers | Read the pointers a human or agent has created (the shared handoff store). With no arguments, lists all pointers |
| `browser_postmessage_audit` | POST /api/security/postmessage | Enumerate postMessage listeners, grade origin checks (none/weak/strict), screen with synthetic MessageEvents |
| `browser_press_key` | POST /api/key | Send a key press, optionally to a focused/targeted element. Keys: Enter, Tab, Escape, arrows, Home, End, etc. |
| `browser_property` | POST /api/property | Read a live DOM property (value, checked, selectedIndex, disabled, …) — not snapshot attributes. |
| `browser_race_lab_baseline` | POST /api/race-lab/baseline | Race Lab baseline pass: fire each configured request once sequentially. REST: POST /api/race-lab/baseline. |
| `browser_race_lab_profiles` | GET/POST /api/race-lab/profiles | Race Lab profile presets: list/save/export/import multi-session race profiles (Hammer/Spike/Sequential/Random parameter presets). |
| `browser_race_lab_run` | POST /api/race-lab/run | Race Lab run: sync (optional) → baseline (optional) → configurable burst (Hammer/Spike/Sequential/Random presets). |
| `browser_race_lab_synchronize` | POST /api/race-lab/synchronize | Race Lab latency compensation: measure per-session RTT and compute dispatch offsets before a burst. |
| `browser_record_start` | POST /api/record/start | Start interaction recording. Captures human DOM actions (clicks, typing) into a .csx script — not MCP/REST tool calls. |
| `browser_record_status` | GET /api/record/status | Whether interaction recording is active, plus startUrl, startedAt, and actionCount. |
| `browser_record_stop` | POST /api/record/stop | Stop interaction recording and return the .csx script and narration. |
| `browser_repro_capture` | POST /api/repro/capture | Capture a .trw repro from journal actions since a checkpoint. |
| `browser_repro_verify` | POST /api/repro/verify | Replay a captured .trw, evidence bundle, or workflow k times. |
| `browser_resource_compare` | POST /api/resource/compare | Compare a saved resource baseline to the current page after you perform actions yourself |
| `browser_resource_probe` | POST /api/resource/probe | Detect possible memory/resource leaks by repeating the same actions or page reloads, forcing GC, and comparing metrics. |
| `browser_resource_snapshot` | POST /api/resource/snapshot | Take a point-in-time resource usage snapshot via CDP: JS heap (after GC), DOM node count, |
| `browser_run_script` | POST /api/execute-script | Execute a C# (.csx) automation script with full Trowser API access (Navigate/Click/Assert.* — not MCP JSON). |
| `browser_saml_capture` | POST /api/security/saml-capture | Capture SAML assertions during SSO login flows. Four modes: |
| `browser_saml_decode` | POST /api/security/saml-decode | Decode SAMLRequest/SAMLResponse from network log or raw input (Redirect/POST bindings) with security checks |
| `browser_saml_replay` | POST /api/security/saml-replay | Replay a captured SAML assertion with modifications for security testing. |
| `browser_screenshot_compare` | POST /api/screenshot/compare | Compare two screenshots pixel-by-pixel for visual regression testing. |
| `browser_scripting_help` | GET /api/scripting-help | Returns a curated C# scripting (.csx) cheat sheet for Trowser (REST: GET /api/scripting-help?topic=…). |
| `browser_scroll` | POST /api/scroll | Scroll the page (direction) or bring a targeted element into view (scrollIntoView). |
| `browser_security` | POST /api/security | Passive security overview on the current page (same modules as Quicktests → 1 Security Scan): |
| `browser_security_account_enumeration_scan` | POST /api/security/account-enumeration-scan | Account enumeration — REST user-list leak, login valid/invalid differential, registration duplicate email. |
| `browser_security_api_inventory` | POST /api/security/api-inventory | OpenAPI/spec vs observed API inventory: tags paths as documented, shadow, or zombie-candidate; |
| `browser_security_auth_bypass_pivot` | POST /api/security/auth-bypass-pivot | Captures a token (session, JWT analyze, or optional SQLi login bypass) and retests protected endpoints. |
| `browser_security_auth_control_identifier` | POST /api/security/auth-control-identifier | Identify which cookies, headers, and token fields actually gate a request: baseline replay, then omit and one-character-… |
| `browser_security_auto_scan` | POST /api/security/auto-scan | Attack-surface-to-scan pipeline: discover endpoints from traffic (+ optional OpenAPI enrichment), then run targeted scan… |
| `browser_security_bfla_probe` | POST /api/security/bfla-probe | Broken Function Level Authorization probe: sends POST/PUT to admin paths using the current session cookies. |
| `browser_security_body_size_limit_scan` | POST /api/security/body-size-limit-scan | Body-size limit probe: escalating tiers 1 KB → 64 KB → 256 KB → 1 MB (one request per tier) on POST endpoints. |
| `browser_security_brute_force` | POST /api/security/brute-force | Sends N sequential failed login attempts with wrongPassword to measure lockout/rate-limit signals (status, body snippets… |
| `browser_security_cache_deception_scan` | POST /api/security/cache-deception-scan | Web Cache Deception (WCD) scanner. Probes delimiter path variants (/api/me/.css, ;.css, etc.) |
| `browser_security_cache_map` | POST /api/security/cache-map | Cache identification + key-mapping indication. Unique ?trowser_cb= busters only — does not poison the live URL. |
| `browser_security_cache_poison_scan` | POST /api/security/cache-poison-scan | Classic web cache poisoning scanner. Injects canary values via unkeyed headers |
| `browser_security_cache_pollution_scan` | POST /api/security/cache-pollution-scan | Live-key error pollution: miss-forcing header on the clean URL, then error-inducing headers, then a fully clean GET. |
| `browser_security_callbacks` | POST /api/security/callbacks | Out-of-band (OOB) interaction detection for blind vulnerability testing. |
| `browser_security_captcha_replay_scan` | POST /api/security/captcha-replay-scan | CAPTCHA / challenge replay: fetch captcha credentials, submit twice to gated endpoints with same token; flags broken sin… |
| `browser_security_chain_analyze` | POST /api/security/chain-analyze | Attack chain discovery: analyzes shadow, auto-scan, and manual findings against built-in chain patterns |
| `browser_security_chain_patterns` | POST /api/security/chain-patterns | List or manage attack chain patterns. |
| `browser_security_chain_prove` | POST /api/security/chain-prove | Execute a built-in proof template for a chain patternId. |
| `browser_security_clickjack_test` | POST /api/security/clickjack-test | Clickjacking / UI redressing: passive X-Frame-Options / CSP frame-ancestors plus optional active cross-origin iframe pro… |
| `browser_security_client_prototype_pollution` | POST /api/security/client-prototype-pollution | Client-side prototype pollution via URL query/hash and postMessage canaries, then optional gadget→sink escalation. |
| `browser_security_cmd_canary` | POST /api/security/cmd-canary | Command injection canaries on injectable string parameters. |
| `browser_security_cookie_prefix_bypass` | POST /api/security/cookie-prefix-bypass | Detects __Host-/__Secure- cookie prefix parser normalization bypass via whitespace variants. |
| `browser_security_cookies` | POST /api/security/cookies | Audit cookies against OWASP best practices. |
| `browser_security_cors` | POST /api/security/cors | Audit CORS configuration by probing with various Origin headers. |
| `browser_security_costly_operations` | POST /api/security/costly-operations | Single-request cost risk scan from captured traffic and DOM: large responses, weak paging, heavy routes, bulk input, com… |
| `browser_security_crawl_light` | POST /api/security/crawl-light | Light same-origin crawler: follows <a href> links and enumerates <form action> URLs (GET only, no POST submissions). |
| `browser_security_csrf` | POST /api/security/csrf | CSRF assessment from live page + network log (forms, missing tokens, custom-header replay, optional Referer/JSON probes)… |
| `browser_security_csti_scan` | POST /api/security/csti-scan | Client-side template injection (CSTI) scan: navigates with template payloads and checks rendered DOM for arithmetic eval… |
| `browser_security_default_credential_canary` | POST /api/security/default-credential-canary | Default-credential canary: small built-in wordlist against login forms/URLs. |
| `browser_security_deserialization_scan` | POST /api/security/deserialization-scan | Deserialization scan: node-serialize `_$$ND_FUNC$$_` timing, YAML billion-laughs DoS, Java magic-byte and PHP unserializ… |
| `browser_security_discover` | POST /api/security/discover | Discover hidden endpoints, admin panels, config files, and API documentation |
| `browser_security_fail_open_scan` | POST /api/security/fail-open-scan | Fail-open scan: replay traffic-derived sensitive endpoints without session cookies and with invalid JWT. |
| `browser_security_file_upload_scan` | POST /api/security/file-upload-scan | File upload validation: baseline PDF, 200KB oversize, .exe wrong-type, JPEG/PHP polyglot; optional upload XXE (multipart… |
| `browser_security_forced_error_scan` | POST /api/security/forced-error-scan | Stack-trace / verbose error disclosure scan: malformed JSON POST to API endpoints. |
| `browser_security_gadget_chains` | POST /api/security/gadget-chains | Client-side gadget chain orchestrator: ranks runtime gadget-read/proto-read events, then runs tailored |
| `browser_security_graphql_analyze` | POST /api/security/graphql-analyze | GraphQL security analysis (introspection, mutations, batching, aliases, depth/limit, draft access, field suggestions, ra… |
| `browser_security_harvest_ids` | POST /api/security/harvest-ids | Harvest object IDs from network log and DOM; suggests authz/boundary tests. |
| `browser_security_headers` | POST /api/security/headers | Analyze HTTP response headers for security misconfigurations. |
| `browser_security_help` | (MCP only) | Short MCP security testing playbook: browse → attack surface → targeted scans → verify. No parameters. |
| `browser_security_host_header` | POST /api/security/host-header | Host header injection scanner via raw TCP HTTP probing. Tests Host override, X-Forwarded-Host, |
| `browser_security_idor_scan` | POST /api/security/idor-scan | Fetches a URL/body template with exactly one §id§ or {{id}} marker for multiple id values; compares fingerprints. |
| `browser_security_js_audit` | POST /api/security/js-audit | Fetch external script[src] bundles from the current DOM and run heuristic scans for hardcoded credentials, |
| `browser_security_js_libraries` | POST /api/security/js-libraries | Retire.js scan for known vulnerable JavaScript library versions on the current page. |
| `browser_security_jwt_acceptance_sweep` | POST /api/security/jwt-acceptance-sweep | Tests endpoints for missing authentication, JWT alg:none, and alg-header variants (cookie-isolated). |
| `browser_security_jwt_analyze` | POST /api/security/jwt-analyze | Decode JWT-shaped tokens from document cookies (including HttpOnly cookies via the browser cookie jar), |
| `browser_security_jwt_forge` | POST /api/security/jwt-forge | Build a modified JWT (JWS) for security testing: merge header/payload, set nested claims via dot-path keys |
| `browser_security_jwt_header_abuse` | POST /api/security/jwt-header-abuse | Tests JWT jku/x5u SSRF and kid injection/path-traversal on protected endpoints. |
| `browser_security_ldap_scan` | POST /api/security/ldap-scan | LDAP filter injection on login endpoints: baseline 401/403 then filter break-out payload. |
| `browser_security_llm_chat_interact` | POST /api/security/llm-chat-interact | Send one prompt through the page chat UI and return responseText/responseHtml. |
| `browser_security_llm_endpoint_discover` | GET or POST /api/security/llm-endpoint-discover | Discover LLM/chat integration: network log chat/completion APIs (including SSE text/event-stream and form-urlencoded pro… |
| `browser_security_llm_http_mcp_list` | POST /api/security/llm-http-mcp-list | Discover/list tools on an HTTP JSON-RPC MCP endpoint (initialize → tools/list). |
| `browser_security_llm_http_send` | POST /api/security/llm-http-send | One-shot: send a prompt over a discovered (or explicit) LLM HTTP endpoint with inferred customBody. |
| `browser_security_llm_redteam_probes` | GET /api/security/llm-redteam-probes | List LLM red-team probe catalog: probe IDs, categories, coverage metadata (covered vs notCoveredInCorpus). |
| `browser_security_llm_redteam_scan` | POST /api/security/llm-redteam-scan | OWASP LLM Top 10 app-layer red-team scan (YAML corpus + optional RAG/peer/consumption/WebMCP). HTTP adapter or chat UI. |
| `browser_security_llm_sink_assist` | POST /api/security/llm-sink-assist | Assistive LLM→XSS path: instrument sinks, optional mock of chat API with canary HTML, return canaryExecuted. |
| `browser_security_logout_invalidation_probe` | POST /api/security/logout-invalidation-probe | Logout invalidation — replay protected endpoint with pre-logout cookie after logout. |
| `browser_security_mass_assignment_patch` | POST /api/security/mass-assignment-patch | PATCH/PUT self-promote mass-assignment probe (OWASP WSTG-INPV-20 / API mass-assignment): discovers profile update endpoi… |
| `browser_security_mass_assignment_register` | POST /api/security/mass-assignment-register | Registration mass-assignment scaffold: probes signup/register endpoints with extra privileged fields. |
| `browser_security_mass_assignment_scan` | POST /api/security/mass-assignment-scan | Sends a baseline JSON or application/x-www-form-urlencoded request, then re-sends with extra privileged fields (role, Us… |
| `browser_security_methods` | POST /api/security/methods | Test which HTTP methods are allowed on a URL. Sends GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, and TRACE |
| `browser_security_missing_parameter_scan` | POST /api/security/missing-parameter-scan | Missing-parameter scan: omit each top-level JSON field on traffic-derived POST bodies; flags 500+stack traces and NPE fi… |
| `browser_security_nextjs_rsc_scan` | POST /api/security/nextjs-rsc-scan | Next.js RSC / Flight deserialization probe (CVE-2025-66478 class): fingerprint App Router, enumerate action hashes, send… |
| `browser_security_nosql_scan` | POST /api/security/nosql-scan | NoSQL injection scan: operator payloads on query strings and JSON login/search endpoints. |
| `browser_security_nuclei_scan` | POST /api/security/nuclei-scan | Run curated nuclei HTTP templates (embedded subset and/or your own) against one or more target URLs. Supports |
| `browser_security_nuclei_templates` | GET /api/security/nuclei-templates | List the runnable nuclei templates (embedded subset and/or a user templatesDir) without scanning: |
| `browser_security_oauth_flow_test` | POST /api/security/oauth-flow-test | OAuth2/OIDC authorization-flow checks from captured /authorize+callback traffic (state/PKCE/implicit/mix-up) |
| `browser_security_oidc_analyze` | POST /api/security/oidc-analyze | OIDC session dossier, optional provider metadata, and relying-party JWT checks. |
| `browser_security_open_redirect_scan` | POST /api/security/open-redirect-scan | Open redirect scanner (CWE-601). Discovers redirect/url/next/return_to parameters from network log |
| `browser_security_osv_check` | POST /api/security/osv-check | OSV.dev enrichment for a raw manifest body without web fetch — useful for testing manifest parsers and advisory lookup o… |
| `browser_security_parser_probe` | POST /api/security/parser-probe | Parser differential probe: tests JSON POST/PUT/PATCH endpoints with Content-Type matrix (XML, form, multipart, java-seri… |
| `browser_security_password_reset_weak_scan` | POST /api/security/password-reset-weak-scan | Weak password-reset via security questions — fetch question, try canonical answers. |
| `browser_security_path_filter_bypass` | POST /api/security/path-filter-bypass | Path-filter bypass probes (NUL byte, double-encoding) on static file directory bases. |
| `browser_security_path_traversal` | POST /api/security/path-traversal | Path traversal probe. Default mode (query): fuzz path-like query parameters on GET URLs from the log or explicit urls. |
| `browser_security_prototype_pollution_scan` | POST /api/security/prototype-pollution-scan | Server-side prototype pollution: POST __proto__/constructor.prototype payload, GET verify canary echo. |
| `browser_security_race_condition_scan` | POST /api/security/race-condition-scan | Race-condition / TOCTOU scan: discover single-use POST endpoints from traffic, fire concurrent identical POST bursts, fl… |
| `browser_security_rate_limit_audit` | POST /api/security/rate-limit-audit | Observational rate-limit audit (A12): discover login/search/OTP/write endpoints from traffic, run sequential baseline th… |
| `browser_security_redos_scan` | POST /api/security/redos-scan | ReDoS timing oracle: single evil-regex payload per injectable search/filter/email parameter (max 3 payloads, sequential)… |
| `browser_security_reset_token` | POST /api/security/reset-token | Analyze password-reset / verification tokens from network traffic for weak entropy and predictable patterns. |
| `browser_security_response_field_diff` | POST /api/security/response-field-diff | Excessive data exposure probe: compares JSON field paths between two captured identities on the same endpoints. |
| `browser_security_rest_scaffold` | POST /api/security/rest-scaffold | Probes ~20 common REST collection paths for unauthenticated JSON leaks when traffic is sparse. |
| `browser_security_secrets_harvest` | POST /api/security/secrets-harvest | Unified secret/credential harvesting across all browser sources: |
| `browser_security_service_worker_audit` | POST /api/security/service-worker-audit | Structured service worker audit on the current origin: registrations, controlling worker, Cache Storage names, |
| `browser_security_session_fixation_scan` | POST /api/security/session-fixation-scan | Detects session fixation — compares cookies before/after login (excludes CSRF/analytics; ignores stable cookies when a n… |
| `browser_security_session_id` | POST /api/security/session-id | Analyze session identifier cookies for weak entropy and predictable generation (sequential, timestamp-embedded, MD5-of-c… |
| `browser_security_shadow` | POST /api/security/shadow | Ambient Shadow analysis on each navigation (off by default; when on: XSS, Retire.js, Headers, Network, Console errors; s… |
| `browser_security_smuggling` | POST /api/security/smuggling | HTTP Request Smuggling scan via raw TCP. Confirmed = repeated differential 404 (CL.TE/TE.CL canary prefix). |
| `browser_security_source_maps` | POST /api/security/source-maps | Scan the current page for source map exposure and framework debug mode indicators. |
| `browser_security_sqli_login_sweep` | POST /api/security/sqli-login-sweep | SQL injection login bypass sweep: POST form+json on common login paths with tautology payloads. |
| `browser_security_sqli_scan` | POST /api/security/sqli-scan | SQL injection probe with unified findings (id/category/severity/confidence/tier/endpoint/param/payload/evidence/proofHin… |
| `browser_security_sse_audit` | POST /api/security/sse-audit | Audit Server-Sent Events: CORS/credentials screening, sensitive data in events, dangerous EventSource handlers, |
| `browser_security_ssrf_orchestrator` | POST /api/security/ssrf-orchestrator | SSRF orchestrator — one call runs scaffold paths + ssrf-scan (IMDSv2, cloud metadata headers) + |
| `browser_security_ssrf_scan` | POST /api/security/ssrf-scan | SSRF scanner with unified findings (severity/confidence/tier/endpoint/param/nextActions). |
| `browser_security_ssti_polyglot_scan` | POST /api/security/ssti-polyglot-scan | Fast reflected SSTI probe: single GET polyglot payload (${7*7}{{7*7}}<%=7*7%>#{7*7}) across common search/render paths. |
| `browser_security_ssti_scan` | POST /api/security/ssti-scan | SSTI scan with unified findings. Discovers injectable parameters from network log or probes explicit request template. |
| `browser_security_ssti_stored_scan` | POST /api/security/ssti-stored-scan | Stored SSTI: POST template payload to profile fields, GET readback for 13289 marker (137*97). |
| `browser_security_storage` | POST /api/security/storage | Audit localStorage and sessionStorage for security issues. |
| `browser_security_supply_chain_scan` | POST /api/security/supply-chain-scan | Supply chain scan: Retire.js CVEs, third-party/SRI inventory, manifest fetch + OSV.dev advisory lookup, |
| `browser_security_swaggering` | POST /api/security/swaggering | Swaggering: discover OpenAPI/Swagger, inventory shadow APIs, and exercise documented operations with the browser session |
| `browser_security_tech_stack` | POST /api/security/tech-stack | Detect the technology stack of the current page: web servers, frameworks, programming languages, |
| `browser_security_tls_introspection` | POST /api/security/tls-introspection | Passive TLS/certificate introspection for HTTPS origins (handshake + optional CDP). |
| `browser_security_token_entropy` | POST /api/security/token-entropy | Generic security token entropy analysis (CSRF nonces, OAuth state/nonce, custom params). |
| `browser_security_trusted_header_bypass` | POST /api/security/trusted-header-bypass | Trusted-proxy header bypass: replay X-Forwarded-User / X-Real-IP on 401/403 paths. |
| `browser_security_verify` | POST /api/security/verify | Exploit verifier: injects payload via browser fetch (optional), navigates to renderUrl with structured |
| `browser_security_verify_workflow` | POST /api/security/verify-workflow | Primary proof API: setup → trigger → oracle → cleanup workflow with deterministic oracle verdict. |
| `browser_security_waf_bypass` | POST /api/security/waf-bypass | WAF bypass technique probe. Sends a canonical attack payload (SQLi/XSS/LFI by default), detects whether |
| `browser_security_websocket_authz` | POST /api/security/websocket-authz | Cross-identity WebSocket check. |
| `browser_security_websocket_fuzz` | POST /api/security/websocket-fuzz | Active WebSocket message fuzzing. Sends XSS/SQLi/JSON-breaking payload catalogs via websocket/send, |
| `browser_security_workflow_skip_scan` | POST /api/security/workflow-skip-scan | Workflow step-skip: late-stage POST endpoints from traffic; captured-body replay → info observation; minimal {} → medium… |
| `browser_security_xs_leaks` | POST /api/security/xs-leaks | Cross-site leak differential scanner: attacker context (iframe/popup/resource) measures observables |
| `browser_security_xss` | POST /api/security/xss | Audit the page's DOM for XSS-prone patterns. |
| `browser_security_xss_scan` | POST /api/security/xss-scan | Active XSS scan with unified findings. Reflected path uses char-survival fingerprint + context-driven payloads; |
| `browser_security_xssi_scan` | POST /api/security/xssi-scan | Cross-Site Script Inclusion (XSSI) / JSONP assessment: re-GETs script/JSON URLs from the network log (or explicit urls[]… |
| `browser_select_option` | POST /api/select | Select a dropdown option by value. Target with ref (preferred) or selector/semantic locator. |
| `browser_send_message` | POST /api/message | Display a notification message to the human tester in the Trowser UI. |
| `browser_seo` | POST /api/seo | SEO audit of the current page from the live DOM. |
| `browser_session_identity` | GET /api/session/identity | Live session identity introspection: session name, cookies (redacted previews), jwtCookies (alg/exp/iss), storage tokens, inferred auth mechanism. |
| `browser_session_memory` | (built-in Chat only) | Read or update volatile session memory (focus and tasks) used across compacts. |
| `browser_shadow_check` | POST /api/shadow/check | Run Shadow Heavy now on the current page: every loaded Law (page/response/console/heavy triggers) plus heavy quicktests… |
| `browser_snapshot` | GET /api/state | Page state: URL, title, headings, frames[], interactive elements with ref numbers, errors. |
| `browser_sse_connections` | GET /api/sse/connections | List captured Server-Sent Events (EventSource) streams on the active tab. REST: GET /api/sse/connections. |
| `browser_sse_messages` | GET /api/sse/messages | List SSE event messages captured via CDP. REST: GET /api/sse/messages. |
| `browser_ssl_add` | POST /api/ssl/certificates | Add a client certificate (.pfx or .p12) for mutual TLS authentication. |
| `browser_ssl_get_active` | GET /api/ssl/certificates/active | Get the currently active client certificate info, or null if no client certificate is set. |
| `browser_ssl_list` | GET /api/ssl/certificates | List all loaded client certificates for mutual TLS. Shows alias, subject, issuer, thumbprint, |
| `browser_ssl_remove` | DELETE /api/ssl/certificates | Remove a client certificate by alias. |
| `browser_ssl_set_active` | POST /api/ssl/certificates/active | Set which client certificate to use for mutual TLS, by alias. |
| `browser_state_refresh` | POST /api/state/refresh | Force a full page state rescan. Use after DOM mutations (e.g. clicking buttons that add/remove elements, |
| `browser_storage` | POST /api/storage | Read and write browser localStorage and sessionStorage. |
| `browser_structured_text` | POST /api/page-text/structured | Extract all text content from the page in a structured format for proofreading. |
| `browser_surpriseme` | POST /api/surpriseme | Run a random non-destructive quicktest from the embedded Quicktests catalog (same as REST POST /api/surpriseme). |
| `browser_switch_tab` | POST /api/tabs/switch | Switch the active browser tab. All subsequent browser actions will target this tab. |
| `browser_tab_order` | POST /api/tab-order | Verify keyboard tab order with real Tab and Shift+Tab (CDP). Auto-detects open modal dialogs |
| `browser_tabs` | GET /api/tabs | List all open browser tabs with their index, title, URL, owner (human/agent/shared), and which one is active. |
| `browser_take_screenshot` | GET /api/screenshot | Capture a screenshot of the page or an element. Two purposes: |
| `browser_test_data` | GET /api/test-data | Get a random test data string or security payload for form fields, JSON parameters, URLs, and similar inputs. |
| `browser_text` | POST /api/text | Get the inner text of a specific element. Pierces shadow DOM boundaries. |
| `browser_third_party` | POST /api/third-party | Inventory all third-party resources loaded by the page (external scripts, stylesheets, iframes, fonts). |
| `browser_trace` | GET /api/trace | Start/stop/export an action timeline (ordered automation steps). Not a Playwright .zip trace viewer. |
| `browser_trace_input` | POST /api/security/trace-input | Trace payload causality from injection source through network (if any) into the DOM. |
| `browser_type` | POST /api/type | Type into an input/textarea/contenteditable (clears first). Content: value or text (aliases), or html for rich editors. |
| `browser_upload` | POST /api/upload | Assign local file(s) to a file input (CDP). |
| `browser_validate_html` | POST /api/validate-html | Validate the current page's HTML markup using html-validate. |
| `browser_viewport` | GET /api/viewport | Set the browser viewport size for responsive design testing. |
| `browser_vpx_clear` | POST /api/vpx/clear | Clear VPX import state and cross-playbook finding dedup (manual chain findings + auto-scan feed). |
| `browser_vpx_export` | GET /api/vpx/export | Export session security findings as a VPX 1.1 document (Vulnerability Proof eXchange). |
| `browser_vpx_import` | POST /api/vpx/import | Import a VPX 1.1 document (VPX 1.0 also accepted) — registers findings for proof queue, surfaces, runs, assessments, pro… |
| `browser_wait` | POST /api/wait | Wait for an element (ref preferred, or selector/semantic locator). |
| `browser_wait_for_download` | POST /api/downloads/wait | Wait until a matching download reaches completed and the saved file exists on disk (not merely started). |
| `browser_wait_for_final_navigation` | POST /api/wait-for-final-navigation | Wait for a navigation chain to settle (redirects, SSO, auto-submit). quietPeriod ms of no new navigations before return. |
| `browser_wait_for_idle` | POST /api/wait-for-idle | Wait until the network is quiet and CSS animations have stopped (same as POST /api/wait-for-idle). |
| `browser_wait_for_network` | POST /api/wait-for-network | Wait for a specific network request to complete. Matches by URL substring, |
| `browser_webmcp_call` | POST /api/webmcp/call | Call a WebMCP tool registered on the current page. The tool's execute function is invoked with the given arguments. |
| `browser_webmcp_tools` | GET /api/webmcp | Detect and list WebMCP tools registered on the current page via navigator.modelContext. |
| `browser_websocket_close` | POST /api/websocket/close | Close an active WebSocket connection via injected page hook. |
| `browser_websocket_send` | POST /api/websocket/send | Send a message on an active WebSocket connection via injected page hook. |
| `get_test_heuristics` | (embedded resource) | Returns curated test heuristics from the exploratory testing community — data attacks, web testing patterns, |

