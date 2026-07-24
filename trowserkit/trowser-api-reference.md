# Trowser REST API — Quick Reference

Condensed reference for all Trowser endpoints.

> **Endpoint index:** [trowser-api-index.md](trowser-api-index.md) is auto-generated from source (`scripts/generate-api-index.ps1`). Update this file when parameters, examples, or behavior change.

**Base URL:** `http://localhost:6923` · **Auth:** `Authorization: Bearer <api-key>` (except `/api/ping`)

---

## Setup

| Setting | Details |
|---------|---------|
| Default port | 6923 (`--api-port <port>` to override). If the port is in use, automatically tries the next 9 ports. Use `--api-port 0` for any available port. |
| API key | Auto-generated per session; use `--api-key <key>` for stable key |
| Session | `--session <name>` isolates browser data (cookies, storage, cache) per named session under `%LocalAppData%\Trowser\Sessions\<name>\`. Default: `default`. Use different names to run multiple instances with independent sessions from the same exe. |
| Ephemeral | `--ephemeral` uses a temporary session folder deleted on exit (for throwaway test sessions) |
| Safe mode | `--safe` blocks JS execution, scripting, mocking, cookie/storage manipulation, `POST /api/fetch` (+ batch), `POST /api/upload`, `POST /api/fuzz`, `POST /api/storage` (write; same as `/storage/set`), `POST /api/intercept/replay`, `POST /api/load-test`, CSRF/methods/path-traversal/ssrf-scan/**open-redirect-scan** probes, `POST /api/security/verify` (+ batch), `POST /api/security/sqli-scan`, `POST /api/security/js-audit`, `POST /api/security/jwt-analyze`, `POST /api/security/jwt-forge`, `POST /api/security/brute-force`, `POST /api/security/idor-scan`, `POST /api/security/mass-assignment-scan`, `POST /api/security/auto-scan`, `POST /api/security/secrets-harvest`, `POST /api/security/smuggling`, `POST /api/security/host-header`, `POST /api/security/waf-bypass`, `POST /api/security/chain-patterns` **add/remove only**, `POST /api/websocket/send`, `POST /api/websocket/close`, `POST /api/security/websocket-audit`, `POST /api/security/cswsh-test`, etc. **Allowed in safe mode:** `POST /api/security/chain-analyze`, `GET /api/security/chain-findings`, `GET /api/security/chain-patterns`, `POST /api/security/chain-patterns` with `action=list`, `GET /api/orchestrate/playbooks`, `POST /api/orchestrate/dry-run/*`, `POST /api/vpx/render`. Orchestration playbooks (`POST /api/orchestrate/*`) respect the `safetyMode` in the request body — `SecurityPreflight` enforces host-based restrictions and caps mode to `safe` when `--safe-probes-only` is active. |
| Security probes | `--safe-probes-only` forces **non-destructive** IDOR (GET/HEAD/OPTIONS only, no PUT/PATCH/DELETE) and skips **mass-assignment** in `POST /api/security/auto-scan` — overrides explicit JSON if those probes would mutate data. `--dangerous-ok` restores **legacy omission defaults** so omitted `includeMutatingProbes` / `includeIdorMutatingProbes` can enable mutating IDOR (still unsafe on shared environments). |
| Scope | `--scope <patterns>` restricts navigation to matching URL patterns |
| Proxy | `--proxy <url>` routes traffic through HTTP proxy (e.g. OWASP ZAP) |

### Multi-Instance (N-Body) Testing

Run multiple Trowser instances with independent browser sessions for cross-identity security testing (BOLA, IDOR, privilege escalation, stored XSS verification):

```bash
# Instance A — admin session
Trowser.exe --api --session admin --api-port 6923 --api-key admin-key

# Instance B — attacker session
Trowser.exe --api --session attacker --api-port 6924 --api-key attacker-key
```

Register instance B as a peer from instance A, then use `POST /api/peer/fetch` to send requests using B's session cookies. See the **Peer Management** section below.

## Response Format

```json
{"success": true, "data": { ... }}
{"success": false, "error": "Error description"}
```

| HTTP Status | Cause |
|-------------|-------|
| 400 | Missing/invalid field |
| 401 | Missing or invalid API key |
| 403 | Blocked by safe mode |
| 404 | Unknown endpoint |
| 499 | Operation aborted via `POST /api/abort` |
| 500 | Element not found, script error, etc. |
| 503 | Server busy (includes `blockedBy`, `dialogPending` fields) |
| 504 | Operation timed out (navigation/JS execution exceeded 30s) |

## Safety Mode (`safetyMode` parameter)

Security-testing endpoints that send probes to the target server require a `safetyMode` field in the request body:

| Mode | HTTP Verbs | Side Effects | Disabled |
|------|-----------|--------------|----------|
| `passive` | None | Zero outbound probes; only observes captured data | All mutating scans |
| `safe` (default) | GET / HEAD / OPTIONS | No state-changing requests | Write-verb probes, load test, brute force |
| `active` | All verbs | May create/modify test data | High-volume DoS, destructive gadgets |
| `aggressive` | All verbs + stress | May exhaust quotas, trigger WAF bans | Nothing |

Most security endpoints require at least `"safetyMode": "active"`. The legacy `"confirmBackend": true` is accepted as an alias for `"safetyMode": "active"`.

---

## Verbose request trace (`verbose` parameter)

Security scanners are powerful but hard to evaluate and troubleshoot, because the actual HTTP
requests they issue are normally invisible to API callers. Pass `"verbose": true` to any security
scan/probe to make the scan transparent and verifiable: the actual outbound requests it issued
(method, URL, payload, response status, timing) are captured and returned alongside the result.

- **Default:** `false` (zero overhead — nothing is captured when off).
- **REST:** the response gains a top-level `verboseTrace` object: `{ requestCount, dropped, requests: [ { seq, method, url, body, status, elapsedMs, error, transport } ] }`. Present whenever `"verbose": true` was accepted (including `requestCount: 0`).
- **MCP:** the tool result gets an extra text block, `--- Verbose request trace ---`, listing each request (also when zero requests were captured).
- **C# scripts:** wrap any scan in `using var trace = BeginRequestTrace();` and read `trace.Entries`.

Tracing is generic: it captures requests at the browser-fetch and server-side HTTP chokepoints,
so it covers every scanner without per-scanner wiring. Request bodies are truncated and the trace
is capped to keep responses bounded.

---

## Element Addressing

All action endpoints accept elements by **ref**, **CSS selector**, or **semantic locator**:

```json
{"ref": 5}
{"selector": "#submit-btn"}
{"role": "button", "name": "Submit"}
{"label": "Email address"}
{"byText": "Sign in"}
{"placeholder": "Search..."}
{"testId": "submit-btn"}
{"value": "option1"}
```

Ref numbers come from `GET /api/state` → `interactiveElements`. Hidden elements have `ref: -1`. After page changes, re-fetch `/api/state` for fresh refs.

**`byText` matching** is case-insensitive and whitespace-normalized (multiple spaces/tabs/newlines → single space).

**Auto-waiting:** All actions wait up to 5s for element readiness. Override with `"timeout": <ms>`.

**Stale ref detection:** Actions return `staleRefWarning` when page changed since last `/api/state`. Pass `refGeneration` with actions for hard error instead.

---

## Session Log

Unified test journal for real-time LLM collaboration and test narrative.

### GET /api/journal
Returns the unified journal — a timeline of all session activity (actions, notes, bugs, enhancements, observations, charters, test ideas, assertions, messages, errors, screenshots) from both the human tester and LLM. **Gate-free** — safe for passive polling.

| Query Param | Description |
|-------------|-------------|
| `since` | Return entries after this index (exclusive). Use for incremental polling. |
| `last` | Return only the last N entries. |
| `type` | Filter: `action`, `assertion`, `message`, `error`, `screenshot`, `script-output`, or a note kind (`note`, `bug`, `enhancement`, `observation`, `charter`, `testing`, `test-idea`, `user`). `type=bug` extracts only bug reports. |
| `source` | Filter: `api` (LLM/REST), `gui` (human tester), `system` (auto-generated) |
| `tag` | Filter by tag: return only entries that have this tag (case-insensitive) |

Response: `{ entries[], count, total, logging }`. Each entry: `{ index, timestamp, type, kind?, source, summary, details?, severity?, fields?, tags?, url? }`. For `bug`/`enhancement` entries, `fields` contains `steps` (string or array), `actual`, `expected`, `priority`, `oracle`, `notes`.

**Efficient polling pattern:**
1. `GET /api/journal?since=0` → entries 1-3, remember `lastSeen=3`
2. `GET /api/journal?since=3` → only new entries (4, 5…)
3. Empty `entries[]` = no new activity

### POST /api/journal
Add a structured entry to the journal. Entries are classified by `kind` so bugs, enhancements, test ideas and charters can be extracted programmatically later. API actions and assertions are auto-logged; use this endpoint for everything else.

| Field | Required | Applies to | Description |
|-------|----------|------------|-------------|
| `kind` | | all | `note` (default), `user`, `charter`, `testing`, `test-idea`, `observation`, `bug`, `enhancement` |
| `note` | ✅* | all | Primary text / title (`text` and `title` are accepted aliases). *Optional when at least one structured field is given for a bug/enhancement. |
| `severity` | | all | `info`, `low`, `medium`, `high`, `critical` |
| `tags` | | all | Array of strings for grouping/filtering (e.g. `["login", "security"]`). Normalized to lowercase. |
| `url` | | all | Page URL. Auto-captured from the browser if omitted. |
| `steps` | | bug, enhancement | Reproduction steps — a string or an array of strings (e.g. `["Open login", "Enter blank password", "Click submit"]`) |
| `actual` | | bug, enhancement | Actual observed behaviour |
| `expected` | | bug, enhancement | Expected behaviour |
| `priority` | | bug, enhancement | `low`, `medium`, `high`, `critical` |
| `oracle` | | bug, enhancement | Why you believe this is a bug |
| `notes` | | bug, enhancement | Additional notes / workarounds |
| `screenshot` | | all | Path to a screenshot (e.g. from `GET /api/screenshot`) — referenced by path in the journal and export (not embedded) |

Examples:
```json
{ "note": "Login page repaints twice" }
{ "kind": "charter", "note": "Stress the checkout flow", "tags": ["checkout", "stress-test"] }
{ "kind": "test-idea", "note": "Paste 10k-char input into search", "tags": ["search", "edge-case"] }
{ "kind": "bug", "note": "Search doesn't trim whitespace",
  "steps": ["Enter '  foo  ' in search", "Click search button"],
  "actual": "0 results", "expected": "Results for 'foo'",
  "priority": "high", "severity": "high",
  "tags": ["search", "input-validation"],
  "screenshot": "C:\\...\\search-empty.png" }
```

Response includes all stored fields for verification: `{ index, timestamp, type, kind, source, summary, severity, fields, tags, url }`.

Bypasses the gate — always available, even when the server is busy.

### GET /api/journal/export
Render the full journal as a formatted report — Markdown (default) or self-contained HTML. Bugs/enhancements are grouped and priority-sorted. Screenshots attached to entries are referenced by path (linked, not embedded). **Gate-free**.

| Query Param | Description |
|-------------|-------------|
| `format` | `markdown` (default) or `html` |
| `path` | Optional file path to also write the report to disk |
| `json` | If `true`, return `{ format, content, path? }` JSON instead of the raw document |

---

## Page State & Inspection

### GET /api/ping
Health check (no auth). Returns `busy` status and `currentOperation` when another call is in progress.

### POST /api/abort
Force-cancel the stuck operation and return server to idle. Bypasses the gate (works even when busy). Returns `aborted` (the cancelled operation) and `message`. Does not break a **frozen page** (infinite loop); use **`POST /api/force-navigate`** or MCP **`browser_force_navigate`** for CDP recovery.

**Cancellation guarantees:** Abort sets `OperationCancellation` on the active gated request. Scanners that check the token **between probes** (SQLi, XSS, open-redirect, SSRF, auto-scan pipeline steps) stop promptly and the busy gate is released. In-flight single HTTP fetches are **not** hard-killed mid-socket — abort takes effect at the next checkpoint. Composite `auto-scan` / playbooks pass the same token into nested scanners; if a nested tool ignores cancellation, abort may appear delayed until that tool returns. **Partial flush:** budget/cancel returns findings already collected (`partial: true` / `budgetExhausted: true`) — completed scanner hits are not dropped.

### POST /api/force-navigate
Recover a **frozen** page: CDP **`Runtime.terminateExecution`** + **`Page.navigate`** (optional `terminateScripts`, default `true`). Body: `{ "url": "about:blank", "terminateScripts": true }`. **Bypasses the gate**; cancels stuck gated op after success. Same navigation-scope rules as `/api/navigate` except `about:` always allowed.

### GET /api/info
Server version, current URL/title, **`navigationScope`** / **`navigationRestricted`**, assertion/console/network counts.

### GET /api/state
**Main endpoint.** Full page snapshot: **URL**, title, `pageText` (3000 chars default), `headings`, `interactiveElements` (with ref numbers, plus `checked` for radio/checkbox), `imageSummary`, `consoleErrors`, `networkErrors`, `assertionSummary`. The `url` field is always included — no extra call to `/api/info` needed.

When configured, also includes **Shadows** fields: `securityShadow` (Security Shadow — passive audits summary when active), `powerMode` (Trowser Power mode — enabled/showOverlays), and `redTeamWhisper` (contextual attack hints — enabled/notifyGui/lastHints). Same toggles as **Settings → Shadows**.

**`securityPreflight`** — when the network log has traffic but no meaningful interaction requests (XHR/fetch, form POST navigations, or other state-changing calls with bodies), reports `navigationOnly: true` with a recommendation to log in, submit forms, search, add to cart, or run `POST /api/security/crawl-light` before attack-surface / auto-scan.

| Param | Description |
|-------|-------------|
| `?fullText=true` | Return untruncated pageText |
| `?visible=false` | Include hidden elements (those with `ref: -1`). Default: visible only. |
| `?selector=<css>` | Scope pageText and interactiveElements to elements within matching container(s) |
| `?tag=<name>` | Filter elements by tag (`input`, `button`, `a`, `select`, etc.) |
| `?type=<name>` | Filter elements by type/role (`text`, `checkbox`, `submit`, etc.) |
| `?q=<text>` | Filter elements by text/label search (case-insensitive) |
| `?limit=<n>` | Max number of interactiveElements |
| `?sections=<list>` | Comma-separated sections to include (e.g., `interactiveElements,url,title`). Also: `securityShadow`, `powerMode`, `redTeamWhisper`. `refGeneration` always included. |

Filtering does not change ref numbering -- refs remain valid for actions.

### POST /api/state/enrich
Batch-fetch text/attributes for multiple refs in one call.

| Field | Required | Description |
|-------|----------|-------------|
| `refs` | Yes | Array of ref numbers |
| `fields` | Yes | Array of field names (`text`, `href`, `value`, `checked`, `placeholder`, `disabled`, `tag`, `id`, `className`, `name`, `type`, `role`, `title`, `required`, `readOnly`, `maxLength`, `pattern`, `min`, `max`, `step`, `src`, `alt`, `target`, `action`, `method`, `tabIndex`, `contentEditable`, `data-testid`, etc.) |

### POST /api/diff-state
Compare two snapshots by `refGeneration` from `GET /api/state` / `GET /api/interactive`. Returns `elementsAdded`, `elementsRemoved`, `textChanged` (selector + before/after text/value), `urlChanged`, `titleChanged`, `newConsoleErrors`, `newNetworkErrors`. Optional `tabIndex`. Snapshots expire (ring buffer ~96); cleared by `POST /api/clear-all`.

| Field | Required | Description |
|-------|----------|-------------|
| `before` | Yes | Earlier refGeneration |
| `after` | Yes | Later refGeneration |
| `tabIndex` | No | Tab index (default: active) |

### POST /api/state/refresh
Force a full page state rescan after DOM mutations. Use when `GET /api/state` returns empty or stale interactive elements after clicking buttons that add/remove DOM elements. Returns same data as `GET /api/state` with `refreshed: true`.

### GET /api/interactive
Interactive elements only (lighter than full state). Returns `count`, `refGeneration`, `elements`.

### GET /api/screenshot
Capture screenshot. Full page by default, or a specific element with `?ref=N` or `?selector=CSS`.

**Response** is JSON: `{"success": true, "data": {"path": "<file>", "format": "png"}}` — the image is saved to `data.path`. Add `?base64=true` to also get `data.base64` with inline image data. The response is **never** raw image bytes.

| Param | Default | Description |
|-------|---------|-------------|
| `base64` | `false` | Set to `true` to include base64-encoded image data inline (recommended for LLM workflows) |
| `format` | `png` | `png` (lossless) or `jpeg` (smaller — **recommended for LLM workflows**) |
| `quality` | `80` | JPEG quality 1-100 (only with `format=jpeg`) |
| `ref` | _(none)_ | Element ref number — captures only that element |
| `selector` | _(none)_ | CSS selector — captures only the matched element |
| `padding` | `0` | Extra pixels around element (0-200) |
| `filename` | _(auto)_ | Custom filename (without extension). E.g. `?filename=checkout-error` → `checkout-error.png`. Useful in `.trw` scenarios for self-documenting screenshots. If omitted, uses timestamped default. |

**LLM-optimized example:** `GET /api/screenshot?format=jpeg&quality=60&base64=true` — returns a compact JPEG as inline base64 (typically 3-5× smaller than PNG).

**Visual testing workflow:** Save the returned file `path`, perform actions, then use `POST /api/screenshot/compare` to detect visual differences.

### POST /api/screenshot/compare
Compare two screenshots pixel-by-pixel for visual regression testing. Returns a diff image with changed pixels highlighted in red.

| Field | Required | Description |
|-------|----------|-------------|
| `before` | Yes | File path (from `/api/screenshot`) or base64 image data |
| `after` | No | File path or base64. **If omitted, captures the current page** |
| `threshold` | No (30) | Pixel difference sensitivity 0-255. Lower = more sensitive |

Returns: `diffPath`, `diffBase64`, `diffPercent`, `changedPixels`, `totalPixels`, `match` (boolean).

### GET /api/page-text
All visible page text (`document.body.innerText`).

### GET /api/page-text/all
Every non-empty text node, **including hidden/off-screen** content, plus **shadow DOM**. One trimmed segment per line in `data.text` (newline-separated). Excludes `script`, `style`, `noscript`, `template`. Response: `text`, `length`. For deep proof-reading beyond visible text.

### GET /api/page-text/screen-reader
Screen-reader-oriented strings: `alt`, `aria-label`, resolved `aria-labelledby` / `aria-describedby`, `title`, SVG `title` / `desc`, including in shadow DOM. Each line prefixed with `[kind]` (e.g. `[alt]`, `[aria-label]`). Response: `text`, `length`, `lineCount`.

### GET /api/source
Full page HTML source (`document.documentElement.outerHTML`). Includes hidden comments, invisible elements.

### GET /api/console
Browser console messages. Levels: `log`, `info`, `warning`, `error`. **Gate-free** — safe for passive polling.

### POST /api/console/clear
Clear captured console messages. Empty body or `{}`.

### GET /api/network
Network traffic log with optional filters. **Gate-free** — safe for passive polling. Each entry includes `durationMs` (response time in milliseconds, measured from request start to response received).

| Param | Description |
|-------|-------------|
| `?errors=true` | Only 4xx/5xx |
| `?url=<substring>` | Filter by URL (case-insensitive) |
| `?method=<GET\|POST\|...>` | Filter by method |
| `?status=<code>` | Filter by exact status |
| `?statusRange=<min>-<max>` | Filter by inclusive status range (e.g. `500-599`). If set, `status` is ignored |
| `?type=<Script\|Fetch\|...>` | Filter by resource type |
| `?includeBody=true` | Include request/response bodies |
| `?includeHeaders=true` | Include full HTTP headers (including `Set-Cookie` captured via CDP) |

### POST /api/network/clear
Clear captured network entries. Empty body or `{}`. Call after reviewing network data to free memory.

### POST /api/clear-all
Reset all test session state in one call. Clears: console log, network log, cookies, mock rules, intercept rules, assertion counters, network throttle, viewport override, localStorage, and sessionStorage.

Optional body: `{ "preserve": ["cookies", "storage"] }` — categories to keep intact. Accepted values: `cookies`, `storage`, `mocks`, `intercepts`, `throttle`, `viewport`.

### POST /api/clear-session
Lighter reset — clears test artifacts (console, network, assertions, mocks, intercepts, throttle, viewport) but **preserves cookies and web storage**. Use when you need a clean test slate without destroying the user's session.

### GET /api/assertions
Current assertion results: `passed`, `failed`, `total`, `allPassed`, `results[]`. **Gate-free** — safe for passive polling.

---


## Inspiration

### GET /api/inspiration
Get a random testing inspiration message — a creative prompt, heuristic, or lateral-thinking trigger to spark new test ideas. Use it to get inspired, but don't necessarily follow it unless it resonates. **Gate-free**. Response: `{ "message": "..." }`.

---

## Test Data

### GET /api/test-data
Get a random test string or security payload for form fields, JSON parameters, URLs, and similar inputs. Respects the **Online** and **ASCII only** settings from the Test Data dialog (online applies to test strings only). **Gate-free**.

| Query | Default | Description |
|-------|---------|-------------|
| `kind` | active tab in Test Data dialog | `strings` — general test strings (may fetch online when enabled); `payloads` — security payloads from `test_payloads.json` |

Response: `{ "text": "...", "kind": "strings" | "payloads" }`.

Data files live next to `Trowser.exe`: `test_strings.json` and `test_payloads.json`. Both use the same entry shape (`text`, `count`, `timestamp`, `is_ascii`). Edit via **Test Data…** (Ctrl+D) or edit the JSON directly.

**MCP equivalent:** `browser_test_data` with optional `kind`.

---

## Notifications

### POST /api/message
Display a message overlay to the human tester at the bottom of the Trowser window. Bypasses the gate (works even when the server is busy with another operation). The message auto-dismisses after `duration` ms.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `text` | ✅ | — | Message text to display |
| `level` | | `"info"` | Severity: `"info"` (blue), `"warning"` (amber), `"error"` (red) |
| `duration` | | `8000` | Display duration in ms (min 1000, max 60000) |

Response: `{ text, level, duration, message }`.

---

## Navigation

### POST /api/navigate
Open a URL **or** step back/forward in session history (CDP `Page.navigateToHistoryEntry`; works for SPA/history where `execute-js` / keyboard cannot).

| Field | Required | Description |
|-------|----------|-------------|
| `url` | For URL nav | Target address; prepends `https://` if no scheme (never pass `"back"` as URL — use `action`) |
| `action` | For history | `back` or `forward` |

### POST /api/force-navigate
CDP **`Runtime.terminateExecution`** + **`Page.navigate`** — recovers when the page JS event loop is stuck (DoS / infinite loop). Gate-bypass. Fields: `url`, `terminateScripts` (default `true`).

### POST /api/go-back
One step back in history. Same as `{"action":"back"}` on `/api/navigate`.

### POST /api/go-forward
One step forward. Same as `{"action":"forward"}` on `/api/navigate`.

### POST /api/settings/scope
Set **navigation scope** on the running instance (same patterns as Settings / `--scope`). Updates `AutomationContext.NavigationGuard` immediately.

| Field | Required | Description |
|-------|----------|-------------|
| `scope` | Yes | Non-empty scope string (e.g. `https://*.example.com/*`, comma-separated patterns; `*.*` = unrestricted) |

**Response:** `scope`, `navigationRestricted` (`false` when scope is `*.*`).

### GET /api/settings/throttle · POST /api/settings/throttle
**API request pacing** — reduce traffic surges that trigger WAF / bot protection (e.g. DataDome). Independent of **Network Throttling** (`/api/network/throttle`, which simulates slow links). Pacing applies to routes that run through the server gate (most `GET`/`POST` ` /api/*` calls); a small set of **gate-free** read-only `GET` endpoints (e.g. `GET /api/journal`, `GET /api/network`, `GET /api/console`) is excluded so polling stays snappy. Each paced call waits for the RPS window; navigation endpoints add the optional extra delay below.

| Field | Default | Description |
|-------|---------|-------------|
| `maxRequestsPerSecond` | `0` (off) | When &gt; `0`, minimum interval `1000 / rps` ms between the **end** of one operation and the **start** of the next (capped 0.005–200 RPS on POST). |
| `delayBetweenNavigations` | `0` | Extra milliseconds **before** `/api/navigate`, `/api/go-back`, `/api/go-forward`, `/api/wait-for-navigation`, and `/api/wait-for-final-navigation` (0–300000), in addition to RPS spacing. |

**GET** returns current `maxRequestsPerSecond`, `delayBetweenNavigations`, and `minIntervalMs` (0 when RPS is off). **POST** requires at least one field; set either value to `0` to clear that limit. Not cleared by `POST /api/clear-all`.

### POST /api/wait-for-navigation
Wait for next navigation event.

| Field | Default | Description |
|-------|---------|-------------|
| `timeout` | 10000 | Max wait (ms) |

### POST /api/wait-for-final-navigation
Wait through redirect chains (SSO, OAuth, SAML). Returns after `quietPeriod` ms of no new navigations.

| Field | Default | Description |
|-------|---------|-------------|
| `quietPeriod` | 500 | Quiet period after last navigation (ms) |
| `timeout` | 15000 | Max total wait (ms) |

### POST /api/wait-for-idle
Wait for network idle and no CSS animations/transitions.

| Field | Default | Description |
|-------|---------|-------------|
| `quietPeriod` | 500 | Network quiet period (ms) |
| `timeout` | 10000 | Max wait (ms) |

---

## Element Interaction

### POST /api/click
Click an element. Auto-waits for visible + enabled. Auto-waits for navigation on `<a href>` links. Returns `changes` (URL, title, errors) if page changed.

| Field | Default | Description |
|-------|---------|-------------|
| element | *(required)* | `ref`, `selector`, or locator |
| `button` | `"left"` | `left`, `right`, `middle` |
| `clickCount` | 1 | 1=single, 2=double-click |
| `timeout` | 5000 | Auto-wait (ms) |

### POST /api/type
Clear input and type text (or append with `append: true` / `clearFirst: false`). Auto-waits for visible + enabled. Automatically detects **contenteditable** elements (rich text editors) and uses `execCommand('insertText')` for compatibility. Pass `html` to insert formatted HTML.

> **There is no `/api/fill`.** Use `/api/type` (clears first by default). To append without clearing: `"append": true` or `"clearFirst": false`. For one character at a time after a clear, call `/api/type` once then `/api/press` / `browser_press_key` per character.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |
| `text` | No (default `""`) | Text to type |
| `html` | No | HTML content for contenteditable elements (uses `insertHTML`) |
| `append` | No (default `false`) | If `true`, append to existing content instead of clearing |
| `clearFirst` | No (default `true`) | If `false`, append to existing content instead of clearing |

### POST /api/upload
Assign **absolute host file path(s)** to `<input type="file">` via CDP `DOM.setFileInputFiles`. Hidden file inputs are OK. **Blocked in safe mode.**

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator targeting the file input |
| `path` | One of path/paths/base64 | Single fully qualified path on the Trowser machine |
| `paths` | One of path/paths/base64 | Array of fully qualified paths (multi-file inputs) |
| `base64` | One of path/paths/base64 | File bytes (temp file written, then deleted after the call) |
| `fileName` | No | Original name when using `base64` (default `upload.bin`; drives temp extension) |
| `submit` | No (default `false`) | If `true`, submits the parent form after assigning files |
| `timeout` | No | Auto-wait for element (ms) |

### POST /api/find
Search visible page text (default: visible only — filters out hidden/off-screen elements). Returns matches with context, nearest CSS selector, and bounding rect.

| Field | Required | Description |
|-------|----------|-------------|
| `text` | Yes | Text to search for |
| `caseSensitive` | No | Case-sensitive search (default: `false`) |
| `regex` | No | Treat text as regex (default: `false`) |
| `scrollTo` | No | Scroll to Nth match (0-based) |
| `highlight` | No | Highlight matches with yellow background (default: `false`) |
| `visibleOnly` | No | Only search visible text (default: `true`). Set to `false` to include hidden elements. |

### POST /api/find/clear
Remove all find highlights from the page.

### POST /api/select
Select dropdown option by value. Returns `actual` with post-selection DOM state.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |
| `value` | No (default `""`) | Option value to select |

### POST /api/hover
Hover over element (real CDP mouse move). Triggers CSS `:hover`, JS `mouseenter`/`mouseover`.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |

### POST /api/scroll
Scroll page or element.

| Field | Default | Description |
|-------|---------|-------------|
| `direction` | `"down"` | `up`, `down`, `top`, `bottom` |
| `scrollIntoView` | false | Scroll element into viewport center |
| `timeout` | 10000 | Timeout in ms. Prevents hang if page is unresponsive |
| element | *(none)* | Omit to auto-detect scrollable container |

### POST /api/key
Send keyboard key press. Supports modifiers.

| Field | Required | Description |
|-------|----------|-------------|
| `key` | Yes | Key name: `Tab`, `Enter`, `Escape`, `Space`, `Backspace`, `Delete`, arrows, `F1`-`F12`, or character |
| element | No | Target (default: focused element) |
| `modifiers` | No | Array: `"Shift"`, `"Control"`, `"Alt"`, `"Meta"` |

---

## Element Data

### POST /api/text
Inner text of element. **Pierces shadow DOM.**

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |

### POST /api/attribute
HTML attribute value. **Pierces shadow DOM.**

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |
| `attribute` | Yes | Attribute name |

### POST /api/property
Live DOM property (framework-managed: Angular/React/Vue). Use for `value`, `checked`, `selectedIndex`, `disabled`.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator |
| `property` | Yes | Property name |

### POST /api/extract
Extract structured data from repeating elements into JSON array.

| Mode | Request |
|------|---------|
| Table auto-extract | `{"selector": "table.data"}` — columns named from `<th>` headers |
| Field mapping | `{"selector": ".card", "fields": {"name": "h3", "price": ".price", "url": "a@href"}}` |
| Simple list | `{"selector": "ul li"}` — returns `[{text: "..."}]` |

Optional: `limit` (max items). Append `@attr` to sub-selectors for attributes. Use `.` for container itself.

---

## Script Execution

### POST /api/execute-js
Run JavaScript in the page context. Blocked in safe mode.

Single expressions (e.g. `document.title`, `1 + 2`) are evaluated directly. Multi-statement scripts are auto-wrapped in an IIFE and the **last expression is auto-returned** — e.g. `const x = 1; x + 1` returns `"2"` without needing an explicit `return`. Explicit `return` is still supported and is required when the final statement is a control-flow block (if/for/while). Leading comments are stripped automatically. Promises are awaited.

| Field | Required | Description |
|-------|----------|-------------|
| `script` | Yes | JavaScript source to run. **Field name is `script` (not `expression`).** Multi-statement auto-wrapped with last-expression auto-return. |

### POST /api/execute-script
Run C# test script (same engine as CLI mode). Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `script` | Yes | C# script code |

### POST /api/batch
Execute multiple actions sequentially in one request. Avoids stale-ref issues between steps.

| Field | Required | Description |
|-------|----------|-------------|
| `actions` | Yes | Array of `{action, ...params}` |

Supported actions: `click`, `type`, `select`, `text`, `attribute`, `hover`, `scroll`, `wait`, `sleep`.

### POST /api/test-scenario
Run many **REST API** steps in a **single HTTP request** (in-process). Covers the full `/api/*` surface (unlike `/api/batch`, which only supports a small action DSL).

| Field | Required | Description |
|-------|----------|-------------|
| `steps` | Yes* | Array of `{ "method": "GET"\|"POST"\|"DELETE", "path": "/api/...", "id?": "...", "query?": "a=1&b=2" \| { "a": "1" }, "body?": { ... }, "delay?": 2000, "capture?": { "var": "data.path" } }` |
| `file` | Yes* | Path to a `.trw` or `.json` file with the same document shape (`steps`, optional `name`, `stopOnError`, `maxSteps`, `pacingMs` / `globalDelay`) |
| `stopOnError` | No (true) | Stop after the first failing step |
| `maxSteps` | No (250) | Hard cap on steps (max 500) |
| `name` | No | Label for the scenario (also readable from file) |
| `pacingMs` | No (0) | **Global** delay in ms between steps (after the first), in addition to each step’s `delay`. Alias: `globalDelay` (max 300,000). Inline body overrides file. |

\* Provide **`steps`** and/or **`file`**; steps from `file` load first, then any inline `steps` are **appended**.

Paths are case-insensitive. Nested `POST /api/test-scenario` and `POST /mcp` are rejected. Safe mode applies per step. `GET /api/journal/export` requires `query` to include `json=true` (non-JSON responses are not captured). Response includes `pacingMs` applied.

**Step-level features:**
- **`delay`** — Milliseconds to wait _before_ executing the step (max 30,000). Useful for SPAs that need time to settle. Applied **after** any `pacingMs` wait for that step.
- **`capture`** — Object mapping variable names to dot-paths into the response JSON. E.g. `"capture": { "imgPath": "data.path" }` stores the screenshot path. Use `{{imgPath}}` in later step bodies/queries to reference it. Supports array indexing: `data.results[0].id`. Only captures on successful steps. Steps call **Trowser** paths only (e.g. chain `POST` `/api/fetch` with the real app URL in the fetch body); capture reads the wrapped `{ success, data }` shape — values inside a **string** `data.body` are not auto-parsed as JSON.

**`.trw` files** use a [JSON Schema](trowser-scenario.schema.json) — add `"$schema": "./trowser-scenario.schema.json"` (or the full URL) for IDE autocompletion and validation. See `example.trw` for a sample.

---

## Waiting

### POST /api/wait
Wait for element to appear. Does **not** throw on timeout.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `selector`, `ref`, or locator |
| `timeout` | No (5000) | Max wait (ms) |

Returns `found: true/false`.

### POST /api/wait-for-network
Wait for specific network request matching URL substring.

| Field | Required | Description |
|-------|----------|-------------|
| `urlPattern` | Yes | URL substring (case-insensitive) |
| `method` | No | HTTP method filter |
| `status` | No | Expected status code |
| `timeout` | No (10000) | Max wait (ms) |

---

## Assertions

All assertion endpoints accept optional `message` for a custom label. Results accumulate and are retrievable via `GET /api/assertions`.

| Endpoint | Required Fields | Description |
|----------|----------------|-------------|
| `POST /api/assert/page-contains` | `text` | Page text contains string |
| `POST /api/assert/page-not-contains` | `text` | Page text does NOT contain string |
| `POST /api/assert/element-visible` | element | Element is visible |
| `POST /api/assert/element-not-visible` | element | Element is NOT visible (or absent) |
| `POST /api/assert/element-text` | element + `expected` | Element innerText equals value |
| `POST /api/assert/element-contains-text` | element + `expected` | Element innerText contains substring |
| `POST /api/assert/element-attribute` | element + `attribute` + `expected` | Attribute equals value |
| `POST /api/assert/url` | `expected` | Current URL contains substring (case-insensitive) |
| `POST /api/assert/title` | `expected` | Page title contains value (case-insensitive) |
| `POST /api/assert/element-count` | `selector` + `expected` (int) | Element count equals value |
| `POST /api/assert/reset` | *(none)* | Clear all assertion results |

---

## Dialog Handling

### GET /api/dialog
Last native dialog info: `type` (`alert`/`confirm`/`prompt`/`beforeunload`), `message`, `defaultValue`.

### POST /api/dialog/handle
Configure handling **before** the triggering action.

| Field | Default | Description |
|-------|---------|-------------|
| `accept` | true | true=OK, false=Cancel |
| `promptText` | *(none)* | Text for prompt dialogs |

### POST /api/dialog/dismiss
Clear last dialog record.

---

## Cookies

### GET /api/cookies
All cookies for current page. `?name=<name>` for a specific cookie.

### POST /api/cookies/set
Set a cookie. **Required:** `name`. **Optional:** `value`, `domain`, `path`, `secure`, `httpOnly`, `sameSite`. Blocked in safe mode.

### POST /api/cookies/delete
Delete cookie. **Required:** `name`. **Optional:** `domain`, `path`. Blocked in safe mode.

### POST /api/cookies/clear
Delete all cookies. Blocked in safe mode.

---

## Web Storage

### GET /api/storage
Get storage entries. `?type=local|session` (default: `local`), `?key=<name>` for single value.

### POST /api/storage
**Alias of [`POST /api/storage/set`](#post-apistorageset).** Set key/value. **Required:** `key`, `value`. **Optional:** `type` (default: `"local"`). Blocked in safe mode. Use this path if you expect symmetric CRUD-style URLs; behavior is identical to `/api/storage/set`.

### POST /api/storage/set
Set key/value. **Required:** `key`, `value`. **Optional:** `type` (default: `"local"`). Blocked in safe mode.

### POST /api/storage/delete
Delete key. **Required:** `key`. **Optional:** `type`. Blocked in safe mode.

### POST /api/storage/clear
Clear all entries. **Optional:** `type`. Blocked in safe mode.

---

## Viewport (Responsive Testing)

### GET /api/viewport
Current viewport size and available presets.

### POST /api/viewport
Set viewport. Provide `preset` **or** `width`+`height`.

| Preset | Size | Preset | Size |
|--------|------|--------|------|
| SmallPhone | 320×568 | SmallPad | 768×1024 |
| BigPhone | 412×915 | BigPad | 1024×1366 |
| LandscapePhone | 844×390 | Desktop | *(reset)* |
| | | BigDesktop | 1920×1080 |

---

## Screen Curtain (Blind Testing)

Black overlay on the web content area — hides the page visually while screen readers and keyboard navigation keep working. Same as **Ctrl+B** in the GUI.

### GET /api/screen-curtain
Returns `{ "enabled": true|false }`.

### POST /api/screen-curtain
Set or toggle the curtain.

```json
{ "enabled": true }
{ "toggle": true }
```

Response: `{ "enabled": true|false }`.

---

## Tab Management

Each tab has isolated console, network, mocks, and refs.

### GET /api/tabs
List all tabs (index, id, title, URL, isActive).

### POST /api/tabs/new
Open new tab (becomes active). **Optional:** `url`.

### POST /api/tabs/close
Close tab. **Optional:** `tabIndex` (default: active tab). Cannot close last tab.

### POST /api/tabs/switch
Switch active tab. **Required:** `tabIndex` (0-based).

---

## Web MCP (Page-Registered Tools)

### GET /api/webmcp
Detect WebMCP tools registered via `navigator.modelContext`.

### POST /api/webmcp/call
Call a WebMCP tool. **Required:** `tool` (name). **Optional:** `arguments`.

---

## Network Mocking (Fault Injection)

### GET /api/mock
List active mock rules. Blocked in safe mode.

### POST /api/mock
Add mock rule. Replaces existing rule with same `urlPattern`+`method`. Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `urlPattern` | Yes | Glob with `*` wildcards, or substring |
| `status` | No (200) | HTTP status code |
| `body` | No | Response body |
| `method` | No | HTTP method filter (null=any) |
| `headers` | No | Response headers object |
| `delay` | No (0) | Response delay (ms) |

### POST /api/mock/remove
Remove mock rule. **Required:** `urlPattern`. Blocked in safe mode.

### POST /api/mock/clear
Clear all mock rules. Blocked in safe mode.

---

## Network Interception (Request Breakpoints)

### GET /api/intercept
List breakpoint rules and pending (held) requests.

### POST /api/intercept
Add breakpoint rule. Matching requests pause until continued/fulfilled/aborted. Auto-continues after 120s.

| Field | Required | Description |
|-------|----------|-------------|
| `urlPattern` | Yes | Regex pattern matched against full URL |
| `method` | No | HTTP method filter (null=any) |

### POST /api/intercept/remove
Remove rule. **Required:** `urlPattern`.

### POST /api/intercept/clear
Clear all rules and release pending requests.

### POST /api/intercept/continue
Continue pending request. **Required:** `requestId`. **Optional:** `url`, `method`, `headers` (modifications).

### POST /api/intercept/fulfill
Fulfill pending request with custom response. **Required:** `requestId`. **Optional:** `status`, `body`, `headers`.

### POST /api/intercept/abort
Abort pending request (simulates network failure). **Required:** `requestId`.

### POST /api/intercept/replay
Replay a pending request N times concurrently. Original request stays held.
`concurrency` (1–25, default 5), `includeBody` (default false — bodies truncated to 200 chars).
Returns timing stats (avg/min/max/p95), status code breakdown, and per-request results.

---

## Load Testing

### POST /api/load-test
Fire any request N times concurrently. Hard cap: 25.
**Required:** `url`, **`safetyMode`: "active"**. **Optional:** `method` (GET), `headers`, `body`, `bodyBase64`, `bodyFile`, `concurrency` (5), `includeBody` (false), `useBrowserCookies` (false — when true, attaches cookies from the browser jar for the target URL so session-bound endpoints can be load-tested).
Each response in the `responses` array includes `index`, `status`, `ms`, `headers` (full response headers as key-value object — including `Location` for 3xx redirects), `bodySnippet`, `error`. Redirect responses are visible because `AllowAutoRedirect` is disabled.
Response includes `purpose: "rate-limit-audit"`. Blocked in safe mode.
Response same as `/api/intercept/replay`.

---

## Browser Fetch (API Testing)

### POST /api/fetch
Send an HTTP request from the browser context using `fetch()`. Includes the page's cookies, auth tokens, and session state automatically. Relative URLs resolve against the current page origin. Blocked in safe mode.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | Yes | — | Request URL (absolute or relative) |
| `method` | No | `"GET"` | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `TRACE` |
| `headers` | No | — | Request headers as key-value object |
| `body` | No | — | Request body as a string |
| `bodyBase64` | No | — | UTF-8 body as standard Base64 (use when shells mangle quotes). Ignored if `body` is set. |
| `bodyFile` | No | — | Read body from a local file path — avoids shell/JSON escaping entirely. Ignored if `body` or `bodyBase64` is set. |
| `json` | No | — | JSON request body — auto-serialized, auto-sets `Content-Type: application/json` |
| `redirect` | No | `"follow"` | Redirect mode: `follow` (default), `manual` (capture 3xx without following — useful for open-redirect / SAML / OAuth testing), `error` (throw on redirect) |
| `timeout` | No | `30000` | Request timeout (ms) |
| `delayMs` | No | `0` | Optional wait (0–120000 ms) before issuing the in-page `fetch` — use with WAFs when global pacing is not enough. |
| `serverSide` | No | `false` | Use .NET `HttpClient` instead of browser `fetch()`. Bypasses forbidden header restrictions (`Referer`, `Origin`, `Host`, etc.) while still sending the browser's cookies. Not subject to CORS. |

Use `body` for raw string payloads (form-encoded, XML, etc.). Use `json` as a shorthand for JSON — it serializes the value and sets the content type automatically. Precedence: `body` → `bodyBase64` → `bodyFile` → `json`.

**PowerShell body escaping:** Single-quoted JSON strings in PowerShell cannot contain unescaped `'`, which makes SQL injection payloads like `' OR 1=1--` painful to pass via `body`. Three alternatives that avoid the issue entirely:
- **`bodyBase64`** — encode the payload to Base64 first: `$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("' OR 1=1--"))`, then `"bodyBase64": "$b64"`.
- **`bodyFile`** — write the payload to a temp file and pass the path: `Set-Content -Path payload.txt -Value "' OR 1=1--" -NoNewline`, then `"bodyFile": "C:\\path\\to\\payload.txt"`. No escaping needed.
- **Object pipeline** — build the request as a PowerShell object and let `ConvertTo-Json` handle escaping: `$obj | ConvertTo-Json -Compress | Invoke-RestMethod -Method Post ...`.

**`serverSide` mode:** Set `"serverSide": true` to route the request through .NET `HttpClient` instead of the browser's `fetch()` API. This allows overriding [forbidden headers](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name) like `Referer`, `Origin`, and `Host` that JavaScript cannot set. The browser's cookies (including HttpOnly) are still attached. Use this when testing referrer-based restrictions, origin checks, or other header-sensitive server behavior. Not subject to CORS policies.

**TRACE/CONNECT support:** These methods are blocked by browser `fetch()`. When used, Trowser automatically falls back to a server-side HttpClient request. The response includes `"type": "server-side"` and a `note` explaining this.

**Cross-origin redirect handling:** When `redirect: "manual"` is used and the target returns a cross-origin 3xx redirect, browser `fetch()` produces an opaque redirect (status 0, no headers). Trowser automatically detects this and re-issues the request server-side with `AllowAutoRedirect = false`, returning the actual 3xx status code, `Location` header, and response body. The response `type` will be `"manual-server-side"` to indicate the fallback.

Returns: `ok`, `status`, `statusText`, `redirected` (bool), `type` (`"basic"`, `"cors"`, `"manual-server-side"` for cross-origin manual redirects, `"server-side"` for TRACE/CONNECT), `url` (final URL), `headers`, `body`.

### POST /api/fetch/batch
Multiple `fetch()` calls in the browser context. **Body:** `requests` (array of objects with the same fields as `/api/fetch`: `url`, `method`, `headers`, `body` or `bodyBase64` or `bodyFile` or `json`, `redirect`, `timeout`), `concurrent` (default `true`). Use for authenticated race-condition tests (parallel polls, etc.). Blocked in safe mode.

---

## Network Throttling

### GET /api/network/throttle
Current throttle state and presets.

### POST /api/network/throttle
Enable throttling. Provide `preset` **or** custom `downloadKbps`+`uploadKbps`+`latencyMs`.

| Preset | Download | Upload | Latency |
|--------|----------|--------|---------|
| Offline | 0 | 0 | 0 (offline) |
| 2G | 32 KB/s | 6.4 KB/s | 1800ms |
| Slow3G | 50 KB/s | 20 KB/s | 2000ms |
| 3G | 188 KB/s | 38 KB/s | 562ms |
| 4G | 1500 KB/s | 750 KB/s | 170ms |

### DELETE /api/network/throttle
Disable throttling (restore full speed).

---

## Auditing & Analysis

### POST /api/audit-all · POST /api/quicktest
**Full page health in one request** (alias: `/api/quicktest`). Runs: WCAG accessibility, Web Vitals performance, **security** (CVE library scan + DOM XSS + mixed content — see response shape below), HTTP security headers, **cookie security** (OWASP best practices), **storage security** (localStorage/sessionStorage), HTML validation, JS compatibility, link checking, GUI consistency, **smuggling risk** (passive header analysis), **supply chain** (Retire.js + SRI + manifest/CI/CD path probes when `safetyMode: "active"`), **secrets harvest** (passive by default), **security misconfiguration** (document CORS, discover sensitive-path count, HTTP methods on current URL; optional forced-error when `safetyMode: "active"`), and **broken access control** (attack-surface auth summary; active IDOR/rest-scaffold when `safetyMode: "active"`). Set `safetyMode: "active"` to include JS bundle + source-map fetching in the same pass. Each sub-audit is independent — if one fails, the rest still return results.

**Optional body** — union of fields from the individual audits:

| Field | Used by | Default |
|-------|---------|---------|
| `level`, `selector` | Accessibility | `AA`, full page |
| `minIos`, `minAndroid` | Compatibility | iOS 15 / Android 10 |
| `scope`, `external`, `timeoutMs`, `concurrency`, `delayMs` | Link check | `anchors`, `true`, `5000`, `10`, `100` |
| `includeSecretsHarvest` | Secrets harvest | `true` |
| `includeSupplyChain` | Retire.js + SRI + manifest/CI/CD path probes | `true` |
| `includeBrokenAccessControl` | BAC summary + optional active probes | `true` |
| `includeMisconfiguration` | CORS + discover summary + methods (+ optional forced-error) | `true` |
| `includeIntegrityFailures` | SRI + CI/CD/manifest counts + cached parser/deserial/upload findings; optional active probe | `true` |
| `includeActiveIntegrityProbe` | Run deserialization + file-upload micro-scan in integrity block | `true` (needs `safetyMode: "active"`) |
| `includeInsecureDesign` | Race/captcha/workflow-skip cached + shadow counts; optional active micro-scan | `true` |
| `includeActiveInsecureDesignProbe` | Run race-condition + captcha-replay + workflow-skip micro-scans in insecureDesign block | `true` (needs `safetyMode: "active"`) |
| `includeAuthenticationFailures` | Session/reset/cookie passive signals + cached auth scan counts; optional active micro-scan | `true` |
| `includeActiveAuthenticationProbe` | Run sqli-login + default-credential + captcha-replay micro-scans in authenticationFailures block | `true` (needs `safetyMode: "active"`) |
| `authProbeTimeoutMs` | Per-request timeout for active auth probes in audit-all | `12000` |
| `authSqliMaxLoginUrls` | Cap sqli-login-sweep in audit-all active auth probe | `4` |
| `authDefaultCredMaxTargets` | Cap default-credential canary targets in audit-all | `2` |
| `authDefaultCredMaxPairs` | Cap credential pairs in audit-all canary | `4` |
| `authCaptchaMaxCandidates` | Cap captcha-replay submit targets in audit-all | `3` |
| `insecureDesignMaxCandidates` | Cap per active insecure-design scanner in audit-all | `4` |
| `insecureDesignProbeTimeoutMs` | Per-request timeout for active insecure-design probes | `8000` |
| `insecureDesignBurstSize` | Concurrent burst size for race probe in audit-all | `15` |
| `includeForcedErrorInMisconfig` | Stack-trace probe inside misconfig block | `false` (needs `safetyMode: "active"`) |
| `forcedErrorMaxEndpoints` | Cap for forced-error in audit-all | `8` |
| `includeIdorInAuditAll` | Read-only IDOR slice when `safetyMode: "active"` | `true` |
| `includeJwtAcceptanceSweep` | JWT alg:none sweep in audit-all | `false` |
| `includeApiInventory` | OpenAPI vs traffic inventory (`specVsObserved`, `versionClusters`) | `true` |
| `includeAuthDeltaProbes` | Session-only endpoint probes inside apiInventory | `false` (needs `safetyMode: "active"`) |
| `includeClickjack` | Clickjacking sweep (passive; active when `includeClickjackActive` + `safetyMode: "active"`) | `false` |
| `includeClickjackSweep` | Sweep sensitive URLs in clickjack pass | `true` |
| `includeClickjackActive` | Active iframe proof in clickjack pass | `false` (needs `safetyMode: "active"`) |
| `includeAiIntegration` | LLM surface discovery + passive AI-traffic signals | `true` |
| `includeActiveLlmRedteam` | Run llm-redteam-scan subset in aiIntegration block | `false` (needs `safetyMode: "active"`) |
| `llmRedteamMaxProbes` | Cap probes when active LLM red-team in audit-all | `8` |
| `safetyMode` | `"active"` enables secrets harvest (JS bundles, source maps) and BAC active probes. (`confirmBackend: true` accepted as legacy alias) | `"safe"` |
| `maxBytesPerFile` | Secrets harvest JS read cap | `524288` |

**Response `data`:** `elapsedMs`, `summary` (`allPassed`, per-audit booleans including … **`insecureDesignClean`**, **`authenticationFailuresClean`**, **`apiInventoryClean`**, **`clickjackClean`**), then … **`insecureDesign`**, **`authenticationFailures`**, **`apiInventory`**, **`clickjack`**.

**`data.authenticationFailures`** — passive session-id grade, reset-token entropy, cookie flags, cached auto-scan auth categories, OAuth/SAML shadow counts; with `safetyMode: "active"` and `includeActiveAuthenticationProbe: true` runs sqli-login-sweep + default-credential-canary + captcha-replay micro-scans:

| Key | Description |
|-----|-------------|
| `isClean` | No auth-related cached/shadow/passive/active findings |
| `cachedAutoScanFindings` | `{ sqliLoginSweep, defaultCredentials, sessionFixation, passwordResetWeak, accountEnumeration, logoutInvalidation, jwtAcceptanceSweep, authBypassPivot, nosql, ldap, total }` |
| `shadowFindings` | `{ oauthOidc, saml, total }` |
| `passiveSignals` | `{ sessionIdEntropyGrade, resetTokenFindingCount, sessionCookieFlagGaps }` |
| `activeAuthenticationProbe` | `{ sqliLoginSweep, defaultCredentialCanary, captchaReplay }` when active |
| `issueCount` | Total across all sources |

**`data.insecureDesign`** — cached auto-scan + Security Shadow counts for race/captcha/workflow-skip; with `safetyMode: "active"` and `includeActiveInsecureDesignProbe: true` runs micro-scans:

| Key | Description |
|-----|-------------|
| `isClean` | No race, captcha-replay, or workflow-skip findings |
| `cachedAutoScanFindings` | `{ raceCondition, brokenAntiAutomation, workflowStepSkip, total }` |
| `shadowFindings` | Same shape from Security Shadow |
| `activeInsecureDesignProbe` | `{ raceCondition, captchaReplay, workflowSkip }` finding counts when active |
| `issueCount` | Total across cache + shadow + active |

**`data.security`** groups three scans (each matches the corresponding single endpoint’s `data`):

| Key | Same as |
|-----|---------|
| `isClean` | `true` only if CVE, XSS, mixed-content, and source-maps are all clean |
| `cve` | `POST /api/security` |
| `xss` | `POST /api/security/xss` |
| `mixedContent` | `POST /api/security/mixed-content` |
| `sourceMaps` | `POST /api/security/source-maps` |
| *(not in bundle)* | `POST /api/security/js-audit` (static script content / cred heuristics) |

**`data.supplyChain`** — passive Retire.js + third-party SRI; with `safetyMode: "active"` also probes accessible manifest and CI/CD paths and runs OSV on leaked manifests:

| Key | Description |
|-----|-------------|
| `isClean` | No Retire CVEs, no external scripts without SRI, no accessible manifests/CI/CD, no OSV hits |
| `retireVulnerableCount` | Retire.js vulnerable libraries on page |
| `manifestPathsAccessible` | Count of leaked `package.json`/lockfile paths (active when `safetyMode: "active"`) |
| `ciCdPathsAccessible` | Count of exposed CI/CD config paths (active when `safetyMode: "active"`) |
| `vulnerableDeclaredCount` | OSV advisory matches from leaked manifests |

Run `POST /api/security/supply-chain-scan` for full manifest parse, CI/CD heuristic analysis, and JS bundle fingerprinting.

**`data.smuggling`** — passive HTTP request smuggling risk assessment (header analysis only, no active probing):

| Key | Description |
|-----|-------------|
| `isClean` | `true` when risk is `none` or `low` |
| `risk` | `none`, `low`, `medium`, `high` |
| `indicators` | Array of risk indicator strings |
| `proxyDetected` | Whether Via/X-Forwarded-For headers suggest a reverse proxy |
| `recommendation` | Next step (run active scan if elevated risk) |

**`protocolLayer`** — A14 protocol-layer rollup (default `includeProtocolLayer: true`):

| Key | Description |
|-----|-------------|
| `isClean` | No elevated smuggling risk and zero protocol-layer issue count |
| `openRedirectCount` | Cached auto-scan open-redirect findings |
| `cacheDeceptionCount` | Cached auto-scan cache-deception findings |
| `cachePoisonCount` | Cache-poison + header-injection chain indicators |
| `smugglingRisk` | From passive smuggling block |
| `smugglingElevated` | `true` when risk is `medium` or `high` |
| `websocketConnections` | Open WebSocket connection count |
| `websocketFindingCount` | Passive websocket-audit finding count |
| `issueCount` | Combined indicator count |
| `recommendation` | Suggested protocol-layer scans when elevated |

**MCP:** `browser_audit_all` — same optional arguments; returns formatted JSON text.

### POST /api/surpriseme
Run a **random non-destructive quicktest** from the embedded Quicktests catalog (same pool as the GUI **SurpriseMe** quicktest). Category folders are balanced so Security does not dominate. Excludes destructive/slow tests (monkey test, fuzz, fault injection, aggressive security scans, etc.).

**No body required.**

**Response:**

| Key | Description |
|-----|-------------|
| `success` | Whether the chosen quicktest completed without script error |
| `quicktest` | Display name of the quicktest that ran (e.g. `LinkCheck`, `PerformanceCheck`) |
| `elapsedMs` | Total execution time |
| `assertions` | `{ passed, failed, total, allPassed }` from the nested quicktest |
| `error` | Script error message when `success` is false |

**MCP:** `browser_surpriseme` — same behavior; returns formatted JSON text.

Blocked in `--safe` mode.

### POST /api/accessibility
WCAG audit (axe-core). **Optional:** `level` (`"A"`, `"AA"`, `"AAA"`, default `"AA"`), `selector` (scope).

### POST /api/tab-order
Keyboard tab-order verification with **real Tab / Shift+Tab** (CDP). Auto-detects open modals (`aria-modal`, `<dialog open>`, popover) and scopes the walk; flags **`modal-focus-leak`** when Tab reaches background under a dialog.

| Field | Default | Description |
|-------|---------|-------------|
| `selector` | — | CSS scope (omit to auto-detect modal or full page) |
| `startSelector` / `start` | — | Element to focus before walking |
| `autoDetectScope` | `true` | Detect modal/popover when selector omitted |
| `strictScope` | `true` | Error when Tab leaves scope |
| `maxSteps` | `150` | Max Tab/Shift+Tab steps per direction |
| `checkPositiveTabIndex` | `true` | Flag `tabindex > 0` |
| `checkSkipped` | `true` | Flag in-scope focusables never reached by Tab |
| `checkReadingOrder` | `true` | Flag large spatial jumps (LTR heuristic) |
| `checkFocusTrap` | `true` | Flag small Tab cycles when many in-scope focusables exist |
| `checkShiftTabConsistency` | `true` | Compare forward vs backward Tab cycles |
| `expectedOrder` | — | Expected sequence (labels, selectors, or ref numbers) |
| `includeSteps` | `true` | Include `forwardSteps` / `backwardSteps` arrays |

**Response highlights:** `focusContextKind`, `focusContextLabel`, `scopeAutoDetected`, `shiftTabConsistent`, `forwardSteps` (with `inScope`), `issues[]`, `summary`.

**MCP:** `browser_tab_order`

### POST /api/performance
Web Vitals: LCP, CLS, INP, TTFB, FCP + navigation timing + resource breakdown. No params needed.

### POST /api/resource/snapshot
Point-in-time resource usage via CDP (after GC prep): JS heap, DOM nodes, documents, frames, event listeners, open WebSockets, optional live `HTMLElement` count. Passive — does not mutate the page.

| Field | Default | Description |
|-------|---------|-------------|
| `rememberBaseline` | `false` | Store this snapshot for the next `POST /api/resource/compare` with `useRememberedBaseline: true` |

**Response highlights:** `heap.usedBytes`, `heap.totalBytes`, `dom.nodes`, `dom.listeners`, `connections.webSocketsOpen`, `flags[]`, `summary`.

**MCP:** `browser_resource_snapshot`

### POST /api/resource/compare
Compare a saved baseline to the **current** page after **you** perform actions (login flows, navigation, modals, etc.). Returns structured findings (heap/listener/DOM growth clues), not raw heap dumps. Use this when your script or the LLM drives the browser between before/after — not when repeating the same action in a loop (use `/api/resource/probe` for that).

| Field | Default | Description |
|-------|---------|-------------|
| `baseline` | — | Snapshot object from `POST /api/resource/snapshot` (`heap`, `dom`, `connections`, `url`, `timestamp`) |
| `useRememberedBaseline` | `false` | Use baseline stored by last snapshot with `rememberBaseline: true` |
| `settleMs` | `500` | Wait before measuring final state |
| `gcBeforeFinal` | `true` | Force GC before final sample |
| `growthThresholdPercent` | `10` | Percent growth that triggers a finding |
| `listenerGrowthThreshold` | `50` | Absolute listener growth threshold |
| `nodeGrowthThreshold` | `100` | Absolute DOM node growth threshold |

**Typical flow:** `POST /api/resource/snapshot` → navigate/click/type via normal APIs → `POST /api/resource/compare` with `baseline` or `useRememberedBaseline: true`.

**Response highlights:** `isClean`, `isLikelyLeak`, `isComparison: true`, `baseline`, `final`, `findings[]` (severity, category, title, description, recommendation, confidence), `summary`.

**MCP:** `browser_resource_compare`

### POST /api/resource/probe
Automated leak probe: baseline → repeat the **same** actions or page reloads N times → GC → compare samples. Use when testing refresh loops or replaying a fixed action sequence — not when you already performed a unique multi-step flow (use `/api/resource/compare`).

Requires **either** `reloadBetweenIterations: true` **or** a non-empty `actions` array (batch format: `{ "action": "click", "ref": 5 }`, etc.).

| Field | Default | Description |
|-------|---------|-------------|
| `actions` | — | Actions replayed each iteration (same format as `/api/interrupter` `actions`) |
| `iterations` | `5` | Measurement iterations after baseline |
| `reloadBetweenIterations` | `false` | Reload current URL at start of each iteration |
| `gcBetweenIterations` | `true` | Force GC before each sample |
| `settleMs` | `500` | Wait after actions before measuring |
| `growthThresholdPercent` | `10` | Percent growth threshold |
| `listenerGrowthThreshold` | `50` | Absolute listener growth threshold |
| `nodeGrowthThreshold` | `100` | Absolute DOM node growth threshold |

**Safety:** `click` / `type` / `select` / `hover` / `press_key` in `actions` require `safetyMode: "active"`. Reload-only probes are passive.

**Response highlights:** Same shape as compare, with `isComparison: false` and `samples[]` for each iteration.

**MCP:** `browser_resource_probe`

### POST /api/security
JavaScript CVE scan (Retire.js). No params needed. Detects libraries via `func`, `uri`, `filename`. For bundled SPAs and declared dependencies, use `POST /api/security/supply-chain-scan`.

### POST /api/security/supply-chain-scan
Supply-chain security: Retire.js CVEs, third-party/SRI inventory, leaked manifest fetch + OSV.dev, CI/CD pipeline exposure, JS bundle dependency fingerprinting, Retire+OSV cross-check, optional CVE reachability PoCs.

| Field | Default | Description |
|-------|---------|-------------|
| `includeManifestFetch` | `true` | Fetch `package.json`, lockfiles, composer, requirements.txt |
| `includeCiCdProbe` | `true` | Probe `.github/workflows/*.yml`, `Jenkinsfile`, `.gitlab-ci.yml`, Azure/CircleCI/Travis, etc. |
| `includeBundleDeps` | `true` | Fingerprint npm packages from JS bundles |
| `includeSourceMaps` | `true` | Parse source maps for `node_modules/` paths |
| `includePathFilterBypass` | `true` | Try `/ftp/` NUL bypass for manifests |
| `includeRetireOsvCrossCheck` | `true` | OSV lookup for tech-stack/manifest/bundle deps missed by Retire |
| `includeCveReachability` | `false` | Run CVE exploit primitives — **requires `safetyMode: "active"`** |
| `safetyMode` | — | `"active"` required for `includeCveReachability`. (`confirmBackend: true` accepted as legacy alias) |
| `maxOsvPackages` | `200` | Cap OSV batch size |
| `maxBundleScripts` | `24` | Max `script[src]` bundles to scan |
| `timeoutMs` | `30000` | HTTP timeout per fetch |

**Response includes:** `manifestCount`, `ciCdExposureCount`, `bundleDependencyCount`, `declaredDependencyCount`, `vulnerableDeclaredCount`, `manifests[]`, `ciCdFiles[]` (with `issues[]`), `bundleDependencies[]`, `osvFindings[]`, `findings[]`.

**MCP:** `browser_security_supply_chain_scan`

### POST /api/security/osv-check
OSV.dev enrichment for a raw manifest body (no web fetch). Accepts `package.json`, lockfiles, `requirements.txt`, `composer.json`, `yarn.lock`.

| Field | Default | Description |
|-------|---------|-------------|
| `manifest` | — | Raw manifest body (**required**) |
| `fileName` | `package.json` | Filename for parser selection |
| `ecosystem` | auto | Optional override: `npm`, `PyPI`, `Packagist`, etc. |
| `maxPackages` | `200` | Cap OSV batch size |

**MCP:** `browser_security_osv_check`

### POST /api/security-headers
HTTP security header analysis (OWASP). No params needed. Checks CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server disclosure, deprecated headers, duplicate security headers, and HTTP TRACE method (XST risk).

### POST /api/security/cors
CORS configuration audit. **Default:** document URL only (in-browser XHR preflight) — evil.com, null origin, subdomain attack, scheme downgrade, suffix attack.

**Multi-endpoint sweep:** set `includeAttackSurfaceUrls: true` or `sweep: true` (or pass `urls[]`) to probe document + API candidates from attack surface (`/api/*`, `/graphql`, `/rest/*`) with server-side Origin probes and session cookies. Returns per-endpoint findings and `divergences` vs document baseline.

| Field | Default | Description |
|-------|---------|-------------|
| `includeAttackSurfaceUrls` | `false` | Enable multi-endpoint sweep |
| `sweep` | `false` | Alias for `includeAttackSurfaceUrls` |
| `urls` | — | Explicit URLs to probe in sweep mode |
| `maxUrls` | `14` | Max endpoints in sweep |
| `includeBrowserCookies` | `true` | Session cookies on server-side sweep probes |
| `includeCredentialsProbe` | `true` | Reflected-origin + Allow-Credentials probe with session cookies |

**Response also includes:** `urlsSwept`, `sweepResults[]` (per-endpoint summary), `endpoints[]`.

### POST /api/security/forced-error-scan
Stack-trace / verbose error disclosure probe (malformed JSON POST). **Requires `safetyMode: "active"`.** Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | network discovery | Optional explicit JSON API URLs |
| `payloads` | all | Subset: `truncated_json`, `empty_body`, `xml_instead_of_json`, `oversized_payload`, `invalid_charset`, `null_byte_in_field`, `duplicate_content_type`, `array_instead_of_object`, `nested_recursion` |
| `maxEndpoints` | `12` | Max endpoints |
| `includeNetworkDiscovery` | `true` | Discover JSON POST endpoints from network log |

**MCP:** `browser_security_forced_error_scan`

### POST /api/security/fail-open-scan
Fail-open probe: strip session cookies, invalid JWT, and mock HTTP 500 mid-flow on traffic-derived endpoints. **Requires `safetyMode: "active"`.** Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | network discovery | Optional explicit URLs |
| `maxEndpoints` | `10` | Max endpoints |
| `includeUnauthenticated` | `true` | Cookie-stripped replay |
| `includeInvalidToken` | `true` | Invalid Bearer JWT |
| `includeAfterError` | `true` | POST retry after mock 500 (uses browser fetch + mocks) |
| `skipStaticAssets` | `true` | Skip CSS/JS/images and common static URL patterns |
| `skipAuthSurfaces` | `true` | Skip login/register/oauth paths for unauthenticated checks |
| `skipPublicEndpoints` | `true` | Skip catalog/UX paths (search, languages, homepage) and non-sensitive GETs without Authorization in traffic |
| `registerChainFindings` | `true` | Feed `chain-analyze` |

Categories: `fail-open-unauthenticated`, `fail-open-invalid-token`, `fail-open-after-error`.

**MCP:** `browser_security_fail_open_scan`

### POST /api/security/missing-parameter-scan
Omit each top-level JSON field on traffic-derived POST bodies; flags 500+stack traces and NPE field hints. **Requires `safetyMode: "active"`.** Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | network discovery | Optional explicit POST URLs |
| `maxEndpoints` | `8` | Max JSON POST endpoints |
| `maxFieldsPerEndpoint` | `8` | Max field omissions per endpoint |
| `registerChainFindings` | `true` | Feed `chain-analyze` |

Categories: `missing-parameter-crash`, `missing-parameter-error`, `missing-parameter-npe-hint`.

**MCP:** `browser_security_missing_parameter_scan`

### POST /api/security/trusted-header-bypass
Trusted-proxy header bypass: anonymous GET on 401/403 paths with `X-Forwarded-User`, `X-Real-IP`, etc. **Requires `safetyMode: "active"`.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `paths` / `urls` | admin/actuator scaffold + attack-surface | Optional path or full URL list (both accepted) |
| `headers` | built-in set | Custom header names to test (e.g. `X-Original-URL`, `X-Rewrite-URL`) |
| `headerSets` | — | Custom header sets as `[{ "X-Forwarded-For": "127.0.0.1" }]` |
| `maxTargets` | `20` | Max gated paths |
| `discoverFromAttackSurface` | `true` | Merge admin/internal paths from attack surface |

**Response includes:** `headersTested[]`, `targetsAttempted`, `targetsTested`, `targetsSkipped`. Findings auto-register for `chain-analyze` (`auth-bypass-header-spoof`).

**MCP:** `browser_security_trusted_header_bypass`. Chain category: `auth-bypass-header-spoof`.

### POST /api/security/default-credential-canary
Default-credential canary against login forms/URLs (built-in wordlist includes `admin/admin123`, `admin@juice-sh.op/admin123`, and 20+ common defaults). Complements `POST /api/security/brute-force` (lockout testing). **Requires `safetyMode: "active"`.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `loginUrls` / `loginUrl` | auto | Explicit login URL(s); when set, discovery defaults off |
| `bodyTemplate` / `body` | JSON with §USER§/§PASS§ | Optional body template |
| `contentType` | auto | Optional Content-Type header |
| `method` | `POST` | HTTP method |
| `maxTargets` | `5` | Max login surfaces |
| `maxPairs` | `12` | Max credential pairs (built-in list tried first, then discovered) |
| `includeDiscoveredCredentials` | `false` | When `true`, merges pairs extracted from JS bundles, page HTML, and network log (js-audit / secrets-harvest patterns) |
| `delayMs` | `400` | Delay between attempts |
| `discoverFromPage` | `true` (false if `loginUrl` set) | Detect password forms on current page |
| `discoverFromNetwork` | `true` (false if `loginUrl` set) | Login URLs from network log |

**Response includes:** `discoveredPairsIncluded`, `credentialSources[]` (when discovery enabled).

**MCP:** `browser_security_default_credential_canary`

### POST /api/security/discover
Endpoint/directory discovery.

| Field | Default | Description |
|-------|---------|-------------|
| `wordlist` | `"common"` | `common` (~50, includes CI/CD paths), `full` (~150), `api` (API-focused) |
| `basePath` | `"/"` | Base path prefix |
| `delayMs` | `0` | Milliseconds between requests. `0` = parallel (fast). `> 0` = sequential (avoids 429) |
| `spaMode` | `false` | When `true`, probes a random invalid path to fingerprint the SPA shell and excludes responses that match (same status, title, similar body length; 3xx also compare `Location`). **Any response with API-shaped `Content-Type`** (`json`, `xml`, `text/plain`, etc.) is **never** treated as a shell duplicate — so JSON APIs behind the same reverse proxy stay in `discovered` even when status/length align with the probe. Use on SPAs that return `text/html` for the shell but `application/json` for real API routes |
| `baselineFilter` | `false` | Alias for `spaMode` |
| `spaProbePath` | _(auto)_ | Optional custom probe path for SPA fingerprinting |

**Response** also includes `probeCount` (paths probed), and when `discoveredCount === 0`: `zeroResultReason` (one-line explanation, e.g. SPA shell filter swallowed all hits).

### POST /api/security/crawl-light
Light same-origin crawler (BFS): follows `<a href>` links and enumerates `<form action>` URLs (GET navigation only — no POST submissions). Populates the network log before scanners. Not a full smart-monkey pass. Respects **`host`** when set (playbook orchestrators pass **`scope.host`** automatically).

By default **`excludeLogout: true`** — skips logout / sign-out / SLO-style paths and logout-looking SPA controls so crawl does not terminate the browser session. Override with **`excludeLogout: false`** only when you intentionally want those URLs visited. Combine with **`excludePaths`**, **`excludeUrlPatterns`**, and optional **`includePaths`** for other pages you must not touch.

| Field | Default | Description |
|-------|---------|-------------|
| `host` | current page | Restrict link discovery and navigation to this host (`scope.host` in playbooks). Accepts hostname (`example.com`), `host:port` (`localhost:3010`), or a full origin/URL — same normalization as attack-surface. |
| `maxDepth` | `2` | Max depth from start page (0–5) |
| `maxPages` | `30` | Max pages to visit (1–100) |
| `followLinks` | `true` | Follow same-origin links |
| `enumerateForms` | `true` | Collect form actions |
| `visitFormActions` | `true` | GET-navigate form action URLs |
| `delayMs` | `200` | Delay between navigations (ms) |
| `includePaths` | `[]` | Glob allowlist for path+query (empty = allow all). Examples: `/app/*`, `/api/*` |
| `excludePaths` | `[]` | Glob denylist for path+query. Examples: `/logout`, `/admin/*`, `/settings/delete*` |
| `excludeUrlPatterns` | `[]` | Regex denylist matched against path+query |
| `excludeLogout` | `true` | Skip logout/sign-out/SLO paths and logout-looking click labels |

**Response:** `pagesVisited`, `linksDiscovered`, `formActionsDiscovered`, `networkEntriesBefore`, `networkEntriesAfter`, `visitedUrls[]`, `skippedUrls[]`, `skippedCount`, `excludeLogout`, `errors[]`, `elapsedMs`, `securityPreflight`.

**MCP:** `browser_security_crawl_light`.

### POST /api/security/attack-surface
Auto-generate an attack surface map from **captured network traffic** (endpoints, methods, parameters, auth, response patterns). **`includeApiEnrichment` (default `true`)** also: (1) parses **OpenAPI/Swagger** payloads already in the network log (JSON with `paths` + `openapi`/`swagger`); (2) **GET-probes** common spec paths (`/openapi.json`, `/swagger.json`, `/api-docs`, `/v2/api-docs`, etc.) on the **current page origin** and up to **`maxProbeOrigins`** distinct API hosts from traffic, using the **browser cookie jar** when available; (3) scans external **`script[src]`** bundles for `/api/…`, `/graphql`, `/vN/…`, and `fetch`/axios URL strings (capped by **`maxJsScripts`** / **`maxJsHintPaths`**). Parsed operations and JS hints are **merged** with live traffic endpoints when path keys match (see `discoveredVia` on each endpoint). **OpenAPI YAML** is supported. **Spec-only** discovery works with an empty network log if `spaMode` is set (page URL still required for probes) or after navigation with no XHR yet — otherwise browse first for best traffic coverage.

Set **`spaMode`: `true`** to also include a **runtime DOM map** for SPAs: HTML `<form>` count, **input/textarea/select** fields, and **link** hrefs, using the same **`interactiveElements`** scan as `GET /api/state` (not static HTML). With **`spaMode`**, the call **succeeds if the network log is empty** (`networkLogEmpty: true`, `source: "dom-only"` or `dom-only+api-discovery`) so you can map the current view before or without browsing. With traffic + `spaMode`, `source` is `"network-log+dom"`. `data:` URIs are filtered by default.

**RFC 9116 `security.txt`** (default **`checkSecurityTxt`: `true`**): probes only the **host of the current navigated tab** — `/.well-known/security.txt` then `/security.txt` — using origins from captured traffic for **that** host when known (`scheme://authority`, including ports), otherwise `https://…` / `http://…` on default ports. **`securityTxt`** is usually a single row for that host plus **`securityTxtAdvice`**.

| Field | Default | Description |
|-------|---------|-------------|
| `includeParameters` | `true` | Include query, body, header, and path parameters (plus `requestContentType` and `requestBodySample`) |
| `includeAuth` | `true` | Include authentication analysis (cookies, tokens, CSRF) |
| `includeResponsePatterns` | `true` | Include response body structure, body snippets (first 200 chars, HTML stripped), and content hashes |
| `host` | _(all)_ | Filter to a specific host. Accepts hostname (`example.com`), `host:port` (`localhost:9090`), or a full origin/URL (`http://localhost:9090/…`) — port is ignored; matching uses hostname (+ loopback equivalence). |
| `includeDataUrls` | `false` | Include `data:` URIs in the analysis (default: filtered to reduce noise) |
| `spaMode` | `false` | When `true`, merge `spa` object (form count, `inputFields`/`links` samples) from live page; allow empty network log |
| `checkSecurityTxt` | `true` | When `true`, probe RFC 9116 `security.txt` for the **current tab host** only (`securityTxt`, `securityTxtAdvice`) |
| `includeApiEnrichment` | `true` | Run OpenAPI discovery + JS bundle URL mining and merge into endpoints |
| `includeOpenApiFromNetwork` | `true` | Inspect successful responses in the log for OpenAPI/Swagger JSON |
| `includeOpenApiProbes` | `true` | GET-probe well-known OpenAPI/Swagger URLs (uses session cookies when possible) |
| `includeJsBundleHints` | `true` | Fetch `script[src]` assets and extract API-like path strings |
| `maxProbeOrigins` | `6` | Distinct `scheme://authority` bases for spec probes (cap 20) |
| `maxJsScripts` | `24` | Max `.js` bundles to scan (cap 80) |
| `maxJsBundleBytesPerFile` | `524288` | Bytes read per bundle |
| `maxJsHintPaths` | `200` | Stop after this many unique hinted endpoints (cap 2000) |
| `enrichmentHttpTimeoutMs` | `12000` | Per-request timeout for enrichment HTTP fetches |

**Response** adds `source` (may include `+api-discovery`), `networkLogEmpty`, optional `spa`, **`enrichment`** (probe/spec/JS stats + errors), **`securityTxt`**, **`securityTxtAdvice`**, **`apiInventory`** (when `includeApiInventory: true`), `endpoints[]` with **`discoveredVia`**; see full reference.

| Field | Default | Description |
|-------|---------|-------------|
| `includeApiInventory` | `true` | Add `apiInventory` block: `specVsObserved`, `versionClusters`, optional `authDelta` |
| `includeAuthDeltaProbes` | `false` | Anonymous vs session-cookie GET probes (**requires `safetyMode: "active"`**) |
| `maxAuthDeltaProbes` | `16` | Cap for authDelta probes |
| `registerChainFindings` | `true` | Register shadow-api / zombie-api findings for `chain-analyze` |

### POST /api/security/api-inventory
Dedicated API inventory pass (same enrichment as attack-surface + classification). Tags each path **`documented` | `shadow` | `zombie-candidate`**. **`versionClusters`** groups `/v1`, `/v2`, `/rest` paths and flags **`parallelActive`**. **`authDelta`** lists session-only endpoints (anonymous 401/403 → cookies 2xx).

Accepts the same fields as `POST /api/security/attack-surface` for enrichment (`spaMode`, `includeApiEnrichment`, …) plus `includeAuthDeltaProbes`, `maxAuthDeltaProbes`, `registerChainFindings`.

**MCP:** `browser_security_api_inventory`

### POST /api/security/clickjack-test
Clickjacking / UI redressing. **Passive:** missing X-Frame-Options / CSP `frame-ancestors` (server-side HEAD/GET). **Active** (`safetyMode: "active"`): cross-origin iframe load via opaque-origin parent; optional overlay test on sensitive page (`includeSensitiveOverlayTest`, `sensitiveRef` from snapshot). **Sweep:** `includeAttackSurfaceUrls` / `sweep: true` — document + sensitive attack-surface URLs + default `/login` `/admin` paths (like CORS sweep).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required** `"active"` for active iframe / overlay tests. (`confirmBackend: true` accepted as legacy alias) |
| `includeActiveTest` | `false` | Active framing proof (defaults on when `safetyMode: "active"`) |
| `sweep` / `includeAttackSurfaceUrls` | `false` | Multi-URL sweep |
| `maxUrls` | `12` | Max URLs in sweep |
| `includeSensitiveOverlayTest` | matches active | Transparent overlay over interactive control |
| `sensitiveRef` | — | Ref from snapshot for overlay target |
| `registerChainFindings` | `true` | Register `clickjack-vulnerable` for chain engine |

**MCP:** `browser_security_clickjack_test`

**Chain patterns:** `shadow-api-unauthenticated-mutation`, `shadow-api-csrf`, `zombie-api-parallel-versions`, `clickjack-sensitive-flow`

### POST /api/security/csrf
CSRF assessment from the **live page** and **network log**. (1) Scans **GET forms** on the current page for state-changing fields (password, change/save/delete, etc.) without anti-CSRF hidden inputs (`get-form-no-csrf-token`, medium) or with tokens (`get-form-csrf-spec-violation`, low). (2) Reports successful state-changing requests (**POST/PUT/PATCH/DELETE**) in the log with **no observable** CSRF token (`no-csrf-token`). (3) Passive **GET** traffic with mutation-like query/path (`get-request-no-csrf-token` / `get-request-csrf-spec-violation`). (4) For token-bearing endpoints in the log, replays **missing** and **invalid** tokens. **`includeGet`: `true`** adds active missing/invalid tests for GET requests that already carry CSRF tokens. Browse and submit forms/API calls for network-based POST findings.

**Safety gate:** Requires `"safetyMode": "active"` — sends real requests. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` — confirm that test requests will be sent to the real server. (`confirmBackend: true` accepted as legacy alias) |
| `maxEndpoints` | `5` | Max endpoints that **carry CSRF tokens** to probe with missing/invalid token tests |
| `maxUnprotected` | `10` | Max distinct endpoints to report with **no CSRF token** observed |
| `includeGet` | `false` | Include GET requests that look state-changing (legacy / vulnerable apps) |
| `includeRefererBypass` | `true` | Replay state-changing endpoints with spoofed Referer headers |
| `includeJsonApiProbing` | `true` | Probe JSON API Content-Type / method-override CSRF vectors |
| `includeCustomHeaderProbes` | `true` | Test simple-request CSRF bypass (omit `X-Requested-With`, `Content-Type: text/plain`) |
| `includeSameSiteAnalysis` | `true` | Analyze session cookie SameSite and adjust scenario severity |

**Response:** `endpointsTested`, `unprotectedCount`, `vulnerableCount`, `customHeaderProbesRun`, `sameSiteContext` (`crossSiteCookieRisk`, `summary`, `sessionCookies[]`), `message`, `includeGet`, `stateChangingGetHints[]` (`url`, `reason` — informational GETs that may warrant `includeGet`; hints use path/query **tokens**, not raw substrings, and skip common static file extensions such as `.jpg`), `scenarios[]` (`url`, `path`, `endpoint` alias of `url`, `method`, `testType`, `tokenLocation` — `none observed` when no token).

### POST /api/security/path-traversal
**Query mode (default, `mode` omitted or `query`):** Probes **GET** URLs (same origin as the current page) from the **network log** — or an explicit `urls` list — replacing path-like **query** parameters with traversal payloads. Default parameter names include `file`, `path`, `page`, `doc`, `include`, `template`, `view`, `content`, `folder`, `dir`, `load`, `read`, `resource`, `url`, `src`, `img`, and similar.

**Path mode (`mode`: `path` or `path-append`):** Appends each payload to the **URL path** after `basePath` or each entry in `pathBases` (for vulnerabilities in the path, not the query — e.g. `/app/../../../etc/passwd`). Fetches a baseline per base path, then compares disclosure heuristics. Findings use `paramName`: `(path-append)`.

Compares responses to **baseline** fetches and flags bodies that look like **`/etc/passwd`**, **`win.ini`**, or similar.

**Safety gate:** Requires `"safetyMode": "active"` — issues real GETs. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `mode` | `query` | `query` — fuzz query params; `path` / `path-append` — append payloads to URL path |
| `basePath` | — | Single path prefix for path mode (e.g. app root `/4193…/`); can be absolute URL (path is taken) |
| `pathBases` | — | Multiple path prefixes for path mode |
| `urls` | _(from log)_ | Optional explicit URLs (**query** mode: must include a fuzzable query param) |
| `paramNames` | built-in set | Optional override for **query** mode parameter names |
| `payloads` | built-in set | Optional custom payload strings |
| `maxCandidates` | `12` | Max distinct URLs (**query** mode) or base paths (**path** mode) |
| `timeout` | `15000` | Per-request timeout (ms) |

**Response:** `mode`, `basePath`, `pathBases` (echo), `message`, `candidatesProbed`, `findings[]`.

### POST /api/security/ssrf-scan
Dedicated SSRF scanner. Discovers **URL-like parameters** from the **network log** (query params and JSON/form body fields named `url`, `redirect`, `callback`, `webhook`, etc., or params whose values look like URLs), or accepts explicit `urls` / **`endpointHints`** (when attack surface found redirect params but captured URLs lack query strings) / a `request` template with `§ssrf§` markers.

For **redirect-like** parameters (`redirect`, `next`, `return_to`, …) or endpoints whose baseline returns **3xx**, probes use **`redirect: manual`** so Location headers are captured without following off-site redirects (avoids "Failed to fetch" on open-redirect endpoints).

With **`includeXxe`: true** (default), also discovers **XML POST/PUT/PATCH** endpoints and injects **XXE payloads** (`<!DOCTYPE>` with `SYSTEM` URIs for `file:///etc/passwd`, cloud metadata, XInclude).

Injects the built-in **`ssrf` payload set** (28 payloads: internal IPs, cloud metadata, protocol handlers) plus optional **callback probe URLs** (`callback.trowser.test`). **Callback detection matches the request host only** — callback URLs embedded in query parameters on other sites do not false-positive. Detects **in-band** indicators and **Tier 1 OOB** client-side callbacks (when the browser actually requests the callback host).

**Safety gate:** Requires `"safetyMode": "active"` — issues real requests with SSRF payloads. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | Optional `{ url, method?, headers?, body?|json? }` with `§ssrf§` marker (template mode) |
| `marker` | first marker | Marker name in request template |
| `baselineValue` | `https://example.com` | Baseline substitution for template mode |
| `urls` | _(from log)_ | Optional explicit URLs (discovery mode) |
| `endpointHints` | — | `[{ url, paramNames[], method? }]` — probe params on endpoints without query in captured URL |
| `includeDomDiscovery` | `true` | Scan page hrefs for URL-like params when network log is sparse |
| `paramNames` | built-in set | URL-like parameter names to fuzz |
| `payloads` | built-in `ssrf` set | Optional custom payloads |
| `maxCandidates` | `10` | Max injection points to probe |
| `timeout` | `15000` | Per-request timeout (ms) |
| `callbackWaitMs` | `2000` | Wait before polling Tier 1 callbacks |
| `includeInternalIps` | `true` | Inject internal/metadata IP payloads |
| `includeProtocolHandlers` | `true` | Inject `file://`, `gopher://`, `dict://` |
| `includeCallbackProbes` | `true` | Inject callback probe URLs; auto-starts Tier 1 OOB |
| `includeXxe` | `true` | Probe XML endpoints from network log for XXE-based SSRF |
| `includeUploadXxe` | `false` | Also run upload-path XXE on `/file-upload`, `/api/import`, etc. (multipart + raw XML) |
| `includeScaffoldPaths` | `true` | When no candidates, probe built-in `/api/fetch`, `/api/proxy`, `/api/webhook`, … paths |
| `includeImdsV2Pivot` | `true` | AWS IMDSv2 token → IAM creds pivot; indicator `aws-imdsv2-metadata` |
| `includeCloudMetadataHeaders` | `true` | Send `Metadata-Flavor: Google` / `Metadata: true` on GCP/Azure probes |
| `xxePayloads` | built-in `xxe` set | Optional custom XXE payloads |
| `minConfidence` | `likely` | Minimum confidence to report: `tentative`, `likely`, `confirmed` |
| `includeHygiene` | `false` | Include non-exploitable tiers |
| `depth` | `standard` | Recorded on the unified envelope (`quick` \| `standard` \| `deep`) |
| `callbackDomain` | `callback.trowser.test` | Custom callback domain (Tier 1) |

**Response:** unified security scan envelope (see above). Scanner extras: `extra.type`, `extra.indicator`, `extra.status`, `extra.baselineStatus`, `extra.correlationId`.

**MCP:** `browser_security_ssrf_scan`.

### POST /api/security/ssrf-orchestrator
One-call SSRF assessment: scaffold paths (when discovery empty) → `ssrf-scan` (IMDSv2 pivot, cloud metadata headers) → open-redirect SSRF escalation → JWT jku/x5u abuse → callback poll → chain-analyze (`ssrf-cloud-metadata`). Registers findings for `chain-prove` template `ssrf-cloud-metadata-proof`.

**Safety gate:** Requires `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `includeScaffoldPaths` | `true` | Probe `/api/fetch`, `/api/proxy`, `/api/webhook`, … when log empty |
| `includeImdsV2Pivot` | `true` | AWS IMDSv2 token → creds chain |
| `includeCloudMetadataHeaders` | `true` | `Metadata-Flavor: Google` / `Metadata: true` on app-facing requests |
| `includeOpenRedirect` | `true` | Open redirect scan with SSRF escalation |
| `includeJwtHeaderAbuse` | `true` | JWT jku/x5u SSRF probe |
| `includeChainAnalysis` | `true` | Run chain-analyze after scans |
| `includeActiveSsrfProbe` | — | *(audit-all only)* Run orchestrator micro-scan when `safetyMode: "active"` |

**MCP:** `browser_security_ssrf_orchestrator`.

**audit-all:** `serverSideFetch` block (passive cached counts; set `includeActiveSsrfProbe: true` with `safetyMode: "active"` for active orchestrator).

### POST /api/security/open-redirect-scan
Dedicated **open redirect** scanner (CWE-601). Discovers **redirect-like parameters** (`redirect`, `url`, `next`, `return_to`, `continue`, etc.) from the **network log**, explicit `urls`, or **`endpointHints`** when attack surface lists params but captured URLs have no query string (e.g. DVWA `low.php` with `redirect` in links only).

Probes with external URLs using **`redirect: manual`** (server-side fallback with session cookies for cross-origin 302s) and flags responses where **Location** points off-site. Auto-generates **substring bypass** payloads from observed redirect values (e.g. `info.php?id=1` → `https://probe/info.php`). When direct external probes are rejected (4xx), discovers **allowlisted URL prefixes** from page links (including URL values embedded in same-origin redirect hrefs like `/redirect?to=https://...`) and network traffic, validates candidates (302 vs 406), then probes **null-byte** (`%00`), CRLF (`%0d%0a`), fragment (`%23`), query (`%3F`), and `@`-trick **allowlist-prefix bypasses** — uses the **full observed URL path** as prefix (not just the host). After open redirect confirmed, probes **SSRF escalation** (`file://`, `127.0.0.1`). Includes bypass payloads: protocol-relative (`//`), backslash (`/\`), `@`-trick, `javascript:`, etc. Default probe host: `open-redirect-probe.trowser.test`.

**Null-byte detection:** Detects whitelist bypass even when the Location header contains the whitelisted host (not the probe) — if a null-byte payload gets 302 while direct probes get 4xx, it's flagged as `null-byte-whitelist-bypass` with confidence `confirmed`.

**Cancellation:** Respects `POST /api/abort` — checks cancellation between every probe request. Adaptive bypass phase capped at 80 payloads per candidate with early-exit on first confirmed bypass.

**Safety gate:** Requires `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | _(from log)_ | Optional explicit URLs (discovery mode) |
| `endpointHints` | — | `[{ url, paramNames[], method? }]` — e.g. `{ "url": "https://…/low.php", "paramNames": ["redirect"] }` |
| `paramNames` | redirect-like set | Parameter names to treat as redirect targets |
| `payloads` | built-in bypass set | Optional custom payloads (`{PROBE}` replaced with probe host) |
| `probeHost` | `open-redirect-probe.trowser.test` | Host to detect in Location header |
| `includeDomDiscovery` | `true` | Scan page hrefs, forms, and current URL for redirect params (no network 302 required) |
| `includeAdaptiveBypasses` | `true` | When external probes are blocked, discover allowlist prefixes from page links/network and run null-byte/CRLF/fragment/query bypass combinations (capped at 80 adaptive payloads) |
| `includeSsrfEscalationProbes` | `true` | After open redirect found, probe file:// and internal IPs (severity → high) |
| `includeScaffoldWithExplicit` | `false` | When `urls` / `endpointHints` are set, synthetic `/redirect` and `/api/goto` scaffolds are **skipped** unless this is `true` |
| `maxCandidates` | `12` | Max injection points to probe |
| `timeout` | `15000` | Per-request timeout (ms) |

**Response:** `message`, `candidatesProbed`, `payloadsSent`, optional `warnings[]` (caller-supplied urls/hints that were not probed), `findings[]` (`title`, `category`, `severity`, `confidence`, `endpoint`/`url`, `method`, `paramName`, `payload`, `statusCode`, `baselineStatusCode`, `location`, `indicator`, `evidence`/`snippet`, `bypassTechnique`, `source`).

**Priority:** `urls` / `endpointHints` / DOM-discovered redirect links outrank scaffold paths. If a hinted URL was not probed, `warnings` lists it — do not treat a scaffold-only run as coverage of that hint. Reproduce with `verbose: true` and/or a full `request` template (`?redirect=§redir§`).

**Indicators:** `external-location-redirect`, `protocol-relative`, `substring-filter-bypass`, `allowlist-prefix-bypass`, `allowlist-filter-bypass`, `null-byte-whitelist-bypass`, `dangerous-scheme-redirect`, `ssrf-via-open-redirect`.

**MCP:** `browser_security_open_redirect_scan`.

### POST /api/security/cache-deception-scan
**Web Cache Deception (WCD)** scanner. Probes delimiter path variants (`/api/me/.css`, `;.css`, encoded `/` and `;`) with **authenticated** then **anonymous** GET (`SecurityProbeHttp` — session cookies vs none). Flags when response bodies are byte-equal (cached authed body served to anonymous client). Includes `Cache-Control` / `Age` / `X-Cache` evidence.

**Safety gate:** Requires `"safetyMode": "active"`. **Requires logged-in session.** Wired into `auto-scan` as `includeCacheDeception` (default `true`) when session cookies exist.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `paths` | built-in set | Base paths: `/api/me`, `/account`, `/dashboard`, … |
| `maxCandidates` | `12` | Max variant URLs |
| `minBodySize` | `64` | Minimum body length for confident match |
| `requireSession` | `true` | Skip when no session cookies |
| `timeout` | `15000` | Per-request timeout (ms) |

**MCP:** `browser_security_cache_deception_scan`.

### POST /api/security/cache-poison-scan
Classic **web cache poisoning** scanner. Injects canary values via unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`, `X-Amz-Website-Redirect-Location`, …), then replays a **clean** GET to detect cache persistence. Optional `header-injection` fuzz on `X-Forwarded-Host`.

**Safety gate:** Requires `"safetyMode": "active"`. Uses backend `HttpClient` (not browser `fetch` — arbitrary headers).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | current page | Target URL(s) |
| `headers` | built-in set | Unkeyed headers to probe |
| `canaryHost` | `cache-poison-probe.trowser.test` | Canary host marker |
| `includeBrowserCookies` | `false` | Attach session cookies |
| `includeHeaderInjectionFuzz` | `true` | Fuzz with `header-injection` payload set |
| `cacheReplayDelayMs` | `300` | Delay before clean replay |
| `maxTargets` | `3` | Max URLs |
| `timeout` | `15000` | Per-request timeout (ms) |

**MCP:** `browser_security_cache_poison_scan`.

### POST /api/security/methods
Test which HTTP methods are allowed on a URL. Sends GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, and TRACE requests server-side and reports which are accepted. Flags security issues: TRACE enabled (XST), unrestricted PUT/DELETE (2xx), and **PUT/DELETE/PATCH returning 5xx** (method routed but server error — may indicate broken authorization or unhandled mutating request).

| Field | Default | Description |
|-------|---------|-------------|
| `url` | current page | URL to test |

### POST /api/security/smuggling
HTTP Request Smuggling detection via **raw TCP probing**. Tests for CL-TE, TE-CL, TE-TE obfuscation, duplicate Content-Length (CL-CL), and header normalization weaknesses. Uses **timing-based differential detection** (James Kettle / PortSwigger technique) — does not actually smuggle requests; instead measures whether ambiguous framing causes one layer to stall while the other processes normally. Also fingerprints infrastructure (proxy detection via Via/X-Forwarded-For/X-Cache/CF-RAY headers, HTTP version, server disclosure).

**Safety gate:** Requires `"safetyMode": "active"` — sends specially crafted HTTP requests with ambiguous CL/TE headers. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` — confirm that probes will be sent to the target. (`confirmBackend: true` accepted as legacy alias) |
| `url` | current page | URL to test |
| `techniques` | `["all"]` | `all`, `CL-TE`, `TE-CL`, `TE-TE`, `CL-CL`, `HEADER` |
| `timeoutMs` | `10000` | Per-probe timeout (ms, max 30000). Longer timeouts improve CL-TE/TE-CL detection reliability. |
| `delayThresholdMs` | `3000` | Timing differential (ms) to flag as vulnerable (min: 1000) |
| `teObfuscations` | `true` | Test 14 Transfer-Encoding header mutations (trailing space, tab, capitalization, extensions, etc.) |

**Response:** `url`, `elapsedMs`, `summary`, `probesRun`, `findingCount`, `findings[]` (`technique`, `severity`, `confidence`, `evidence`, `description`, `remediation`, `probeDetails` with `baselineMs`/`probeMs`/`deltaMs`), `headerNormalization` (`acceptsDuplicateCL`, `acceptsObfuscatedTE`, `obfuscationsAccepted[]`, `rejectsBothCLAndTE`), `infrastructure` (`httpVersion`, `serverHeader`, `viaHeaders[]`, `proxyLikely`, `proxyEvidence[]`).

**Passive mode (in audit-all):** The passive smuggling check runs automatically in `POST /api/audit-all` without `safetyMode: "active"` — it only analyzes response headers (no active probing). Reports `risk` (`none`/`low`/`medium`/`high`), `indicators[]`, `proxyDetected`, and `recommendation`.

**MCP:** `browser_security_smuggling` (same parameters; returns formatted text report).

### POST /api/security/host-header
Host header injection scanner via **raw TCP HTTP probing**. Sends manipulated `Host`, `X-Forwarded-Host`, `X-Original-Host`, `Forwarded`, duplicate `Host`, port-variant, and absolute-URL requests; compares poisoned responses against a baseline for reflected host values in redirects, links, and body text. Useful for password-reset poisoning, cache poisoning, and open redirect via Host.

**Safety gate:** Requires `"safetyMode": "active"` — may trigger password-reset emails on vulnerable endpoints. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` — confirm manipulated Host headers will be sent. (`confirmBackend: true` accepted as legacy alias) |
| `url` | current page | URL to test (optional when `discoverFromNetwork` is true) |
| `method` | `GET` | HTTP method for explicit URL |
| `body` | — | Request body (optional) |
| `json` | — | JSON body (sets `Content-Type: application/json`) |
| `headers` | — | Extra request headers |
| `evilHost` | `evil.trowser.test` | Marker host injected into probes |
| `probes` | `["all"]` | Which probes to run. Values: `all` (default — all seven below), or any of: `host-override`, `x-forwarded-host`, `x-original-host`, `forwarded`, `duplicate-host`, `host-port`, `absolute-url` |
| `includeBrowserCookies` | `true` | Attach browser session cookies (HttpOnly included) |
| `discoverFromNetwork` | `false` | Discover password-reset / invite / recovery URLs from network log (deduped by path) |
| `maxTargets` | `5` | Max distinct paths when `discoverFromNetwork` |
| `timeoutMs` | `15000` | Per-request timeout (ms, max 30000) |

**Probes explained:**

| Probe | What it sends |
|-------|---------------|
| `host-override` | `Host: evil.trowser.test` (canonical Host replaced) |
| `x-forwarded-host` | `X-Forwarded-Host: evil.trowser.test` |
| `x-original-host` | `X-Original-Host: evil.trowser.test` |
| `forwarded` | `Forwarded: host=evil.trowser.test` |
| `duplicate-host` | Two `Host` headers (canonical then evil) |
| `host-port` | `Host: evil.trowser.test:9999` (or evil with real port) |
| `absolute-url` | Absolute request-line URL with evil `Host` |

**Response:** `evilHost`, `elapsedMs`, `targetCount`, `findingCount`, `summary`, `discoveredFromNetwork`, `targets[]` (each with `url`, `method`, `reason`, `probesRun` (= length of `probes[]`), `requestsRun` (= `probesRun` + 1 baseline), `findings[]`, `baseline`, `probes[]` with `rawRequest` for reproduction).

**MCP:** `browser_security_host_header` (same parameters; returns formatted text report).

### POST /api/security/waf-bypass
WAF bypass technique probe. Sends a canonical attack payload (SQLi/XSS/LFI by default), compares the response to a benign baseline to detect WAF blocking, then tests classic bypass transforms and reports which appear to reach the backend. **Vendor fingerprinting is out of scope** — use `POST /api/security/tech-stack` or wafw00f for WAF identification.

**Safety gate:** Requires `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` — confirm attack payloads will be sent. (`confirmBackend: true` accepted as legacy alias) |
| `url` | current page | URL with `§PAYLOAD§` / `{{PAYLOAD}}` marker, or plain URL + `paramName` |
| `method` | `GET` | HTTP method |
| `paramName` | — | Query/body param when `url` has no fuzz marker |
| `body` / `json` | — | Body template with marker (POST/PUT) |
| `headers` | — | Extra request headers |
| `category` | `sqli` | `sqli`, `xss`, `lfi`, `custom` — selects default `probePayload` |
| `probePayload` | category default | Canonical attack string (`' OR 1=1--`, `<script>alert(1)</script>`, etc.) |
| `baselineValue` | `1` | Benign substitution for baseline request |
| `techniques` | all | Subset of technique ids (see below) |
| `timeout` / `timeoutMs` | `15000` | Per-request timeout |
| `useBackendFetch` | `false` | Server-side HttpClient instead of in-page fetch |
| `includeBrowserCookies` | `true` | Session cookies when `useBackendFetch` |

**Built-in techniques:** `url-encoding`, `double-url-encoding`, `unicode-overlong`, `mixed-case`, `inline-comment`, `whitespace-variant`, `null-byte`, `concat-break`, `xff-spoof`, `x-real-ip-spoof`, `x-original-url`, `method-override`, `path-normalization`, `param-pollution`, `content-type-form` (POST JSON bodies).

**Response:** `wafBlockDetected`, `wafIndicators[]`, `usableBypasses[]`, `techniques[]` (`technique`, `category`, `verdict`: `blocked`/`bypassed`/`inconclusive`, status/length/timing), `summary`.

**MCP:** `browser_security_waf_bypass` (same parameters; returns formatted text report).

### POST /api/security/shadow · GET /api/security/shadow
Security Shadow Mode — continuous ambient security analysis on every navigation. Runs configurable audits (headers, cookies, xss, mixed-content, source-maps, storage) and accumulates deduplicated findings. **Deduplication** merges findings by `audit + title` across all pages — the same issue (e.g. "No CSP") seen on 7 pages appears once with `occurrences: 7` and a `seenOnUrls` list. Also monitors network traffic for 5xx errors, sensitive data in URLs, and large responses. **On Fetch/XHR/Document responses** (bounded body size in the log), passively flags **SQL error signatures**, **credential/PII-like patterns** (hashes, key-like strings, emails), and **CAPTCHA challenge + answer-like fields** in the same body. The **security-headers** audit reads the **navigation Document response** already in the network log (no extra HEAD/GET to the page — avoids CSRF/session side effects). When active, summary included in `GET /api/state` → `securityShadow`.

**POST — Enable/Configure:**

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable or disable |
| `audits` | `["all"]` | `all`, `security-headers`, `cookies`, `xss`, `mixed-content`, `source-maps`, `storage` |
| `scope` | `"same-origin"` | `same-origin`, `all`, or URL pattern |
| `suggestions` | `true` | Generate proactive testing suggestions |

**GET — Query findings:**

| Param | Description |
|-------|-------------|
| `?status=true` | Counts only (lightweight poll) |
| `?since=<id>` | Findings newer than this ID |
| `?severity=high` | Min severity: `low`, `medium`, `high`, `critical` |
| `?category=headers` | Filter by audit category |

**GET** is **gate-free**. **MCP:** `browser_security_shadow`.

### POST /api/security/shadow/clear
Clear accumulated findings. Optional: `{ "category": "headers" }`.

### GET /api/shadows · POST /api/shadows
**Shadows (testing aids)** — **Power mode** reveals hidden/disabled UI for manual testing (optional Phase 2 overlays: outlines and labels). **Red Team Whisper** generates contextual attack hints after navigation (DOM + light network heuristics); optional GUI toasts when `notifyGui` is on.

**GET** returns current settings: `powerMode` (`enabled`, `showOverlays`), `redTeamWhisper` (`enabled`, `notifyGui`, `lastHints`).

**POST** updates settings (omit a field to leave it unchanged):

| Field | Description |
|-------|-------------|
| `powerModeEnabled` | Master switch for Power mode |
| `powerModeShowOverlays` | Phase 2: outlines/labels on revealed elements |
| `whisperEnabled` | Master switch for Red Team Whisper |
| `whisperNotifyGui` | Show in-app notifications for new hint sets |

**POST** reapplies Power mode on **all open tabs** when Power mode settings change.

**GET** is **gate-free**.

### POST /api/security/firewall-test
Client-side firewall testing — injects real bypass techniques into the live browser and observes whether CSP, SRI, iframe sandbox, and Permissions-Policy actually block them. Not static analysis — active verification.

**Safety gate:** Requires `"safetyMode": "active"`. Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | *(required)* | `"active"` — acknowledge page modification risk. (`confirmBackend: true` accepted as legacy alias) |
| `tests` | `["all"]` | `all`, `csp`, `sri`, `sandbox`, `permissions-policy` |
| `verbose` | `false` | When `true`, includes full per-defense `defenses` with every `findings[]` and `tests[]` entry (evidence, long `detail` strings). When `false` (default), returns a **compact** `results[]` and a multi-line `summary` only. |

CSP tests: inline-script injection, eval(), event handlers, nonce reuse, base-uri injection. SRI: third-party scripts without integrity. Sandbox: sandbox escapes, missing sandbox on cross-origin iframes. Permissions-Policy: restricted API verification.

**Default response:** `elapsedMs`, `overallVerdict`, defense counts, `results[]` rows `{ test, blocked, method, category }`, and `summary` (string). **Verbose response:** same counts + `defenses: { csp, sri, sandbox, permissionsPolicy }` with full `findings` / `tests` (including all per-asset SRI lines).

**MCP:** `browser_firewall_test` (returns the same JSON shape as the REST `data` object, not a plain-text report).

### POST /api/security/trace-input
Input→Network→DOM causality tracing. Supports multiple **injection sources**: form field (type+submit), **url-query**, **url-hash**, **url-path** (navigate with payload — essential for DOM XSS via `location.search` / `location.hash`). Identifies input **filtering vs encoding** (not “sanitization = safe”), server reflection context, **open redirects** (HTTP 3xx with external Location — CWE-601), DOM rendering, CSP, and sink reachability. **Context-aware reflection:** `javascript:` / `data:` URIs are only flagged dangerous in URL attributes — not plain text. DOM analysis uses payload **markers** and dangerous-element detection.

When a **form control filters or constrains** input (e.g. `<select>` truncates payload), the tool does **not** report safety — it notes the coverage gap and, with **`probeUrlSources: true`** (default), automatically probes **url-query** and **url-hash** after form bypass attempts fail.

**Safety gate:** Requires `"safetyMode": "active"`. Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `source` | No | `form` (default), `url-query`, `url-hash`, `url-path` |
| `target` | Yes‡ | CSS selector for input element (**required when `source=form`**) |
| `baseUrl` | No | Base URL for url-* sources (default: current page URL) |
| `queryParam` | No | Query param name for `url-query` (default `q`) |
| `hashParam` | No | Hash param for `url-hash` — omit to use payload as **entire fragment**, or let Trowser **auto-discover** param names from inline scripts (e.g. DVWA `default=`) |
| `queryEncode` | No | `none` (default — raw for DOM XSS via decodeURI/decodeURIComponent), `component`, `form` |
| `fragmentEncode` | No | `none` (default — use for DOM XSS hash bypasses), `component`, `form` |
| `pathEncode` | No | `component` (default), `form`, `none` |
| `probeUrlSources` | No | `true` | After form filtering, auto-probe url-query + url-hash (default `true`) |
| `payload` | One of* | Single payload. With `autoBypass: true`, omit to use default `<script>alert(1)</script>` |
| `payloads` | One of* | Array of payloads (batch). **Not compatible with `autoBypass`** |
| `autoBypass` | No | `true` | Try alternative XSS vectors when primary fails; for url-* sources, retries bypass catalog via navigation |
| `maxBypassAttempts` | No | `10` | Max alternative vectors (max `15`) |
| `submit` | No | CSS selector for submit button (form source) |
| `submitAction` | No | `click` (default), `enter`, `none` |
| `checkCsp` | No | Evaluate CSP protection (default `true`) |
| `detectSqli` | No | Scan **response bodies** for SQL/DB error signatures (default `false`) |
| `monitorSinks` | No | Hook dangerous sinks (`eval`, `innerHTML`, `document.write`, `Function`, etc.) **before** injection. For **url-hash/url-query** navigation, hooks install via `AddScriptToExecuteOnDocumentCreated` so parse-time `document.write` is captured. Payload reaching a sink without CSP blocking → **critical**. Default `false`. |
| `timeout` | No | Max wait ms (default `10000`) |
| `delayMs` | No | `0` | Optional wait before trace starts (0–120000 ms) |

\*Provide `payload`, `payloads`, or `autoBypass: true` (with optional primary `payload`).  
‡Not required for url-* sources.

Single response: **`injection`** (`sourceType`, `treatment`, `constraintType`, `encoding`, `navigatedUrl`, `notes`), `network`, `serverResponse` (`openRedirect`, `redirectLocation`, `redirectHost` when 3xx Location points off-site), `dom`, `csp`, `sinks` (optional), `sqliIndicators` (optional), `verdict`.

**Auto-bypass response:** `primaryPayload`, `primaryOutcome`, `bypassConfirmed`, `bypassSummary`, `bypassAttempts[]`, **`urlProbeAttempts[]`** (form → URL fallback probes), `worstVerdict`, `effectiveTrace`, `primaryTrace`, optional `successfulBypass`.

Batch response: `summary` + `traces[]`.

**MCP:** `browser_trace_input`.

### Unified security scan response (injection scanners)

`sqli-scan`, `xss-scan`, `ssti-scan`, and `ssrf-scan` share one finding contract for LLM/MCP triage:

| Field | Description |
|-------|-------------|
| `id` | Stable finding id |
| `category` | e.g. `sqli`, `xss-dom`, `ssti`, `ssrf` |
| `title` | Short title |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `confidence` | `confirmed` \| `likely` \| `tentative` |
| `tier` | `exploitable` (default filter) \| `hygiene` \| `informational` |
| `endpoint`, `method`, `param`, `payload` | Where / how |
| `evidence`, `proofHint` | Snippet + human-readable proof |
| `nextActions[]` | Suggested follow-ups (`trace-input`, `verify`, boolean retest, callback poll, …) |
| `extra` | Scanner-specific map (`types`, `engine`, `context`, `correlationId`, …) |

**Envelope:** `message`, `depth`, `candidatesProbed`, `payloadsSent`, `elapsedMs`, `hasFindings`, `summary[]`, `findings[]`, optional `details` (rows/baseline/diagnostics).

**Default filters (LLM-friendly):** `tier=exploitable` and `confidence ≥ likely`. Override with `includeHygiene: true` and/or `minConfidence: "tentative"`.

**Depth:** `quick` \| `standard` (default) \| `deep` (aliases: `fast`/`light` → quick; `thorough`/`full` → deep).

### POST /api/security/sqli-scan
SQL injection probe with **unified findings**. Substitutes payloads at **`§marker§` / `{{marker}}`** (same as fuzz). Uses noise-stripped **boolean differentials** (truthy/falsy hash split → `blind-boolean-confirmed`), SPA/payload-reflection FP stripping, **per-probe CSRF token refresh** for mutating methods **and** GET URLs that already carry CSRF query fields (e.g. `user_token`), optional multi-sample time delays, and (depth=`deep`) UNION column ladder + ORM closures.

**Shorthand:** `{ url, param }` injects a literal `§param§` marker into the query string (markers are **not** percent-encoded — `UriBuilder` encoding would break detection), **retains sibling query params**, and (for GET) clones missing form siblings such as `Submit` from the live DOM when a matching form is present. Prefer `{{param}}` in PowerShell if `§` is awkward (`\u00A7param\u00A7` also works in JSON). Body/header injection still needs a full `request` template with markers.

**Boolean confirmation:** `blind-boolean-confirmed` requires a truthy/falsy pair with different noise-stripped bodies **after neutralizing reflected payload text**, plus a **content oracle** (at least one side near the successful baseline). Shared CSRF-fail pages / token-reuse clusters are stripped and never promoted to `confirmed`.

**Example shorthand:**
```json
{ "safetyMode": "active", "url": "http://localhost:3010/api/products?query=test&Submit=Search", "param": "query", "depth": "quick" }
```

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` |
| `request` / `url`+`param` | — | Marker template or shorthand (`param` / `paramName`) |
| `depth` | `standard` | `quick` (screening only) \| `standard` \| `deep` (UNION ladder, ORM, time by default) |
| `baselineValue` | `"1"` | Baseline marker substitution |
| `includeTimeBased` | from depth | SLEEP/WAITFOR/pg_sleep (multi-sample when depth ≥ standard) |
| `payloads` | built-in | Replaces built-in set when provided |
| `timeoutMs` | `15000` | Per-request timeout |
| `maxResponseBodyChars` | `131072` | Max chars scanned for SQL signatures |
| `useBackendFetch` | `false` | .NET HttpClient (avoids Zone.js) |
| `includeBrowserCookies` | `false` | With backend fetch: merge WebView cookies |
| `includeOrmClosurePayloads` | from depth | ORM closure add-ons |
| `minConfidence` | `likely` | Filter findings |
| `includeHygiene` | `false` | Include non-exploitable tiers |

**Response:** unified envelope; `findings[]` collapsed by `(endpoint path, param, class)` with `extra.payloads` / `extra.payloadCount`; `details` includes `baseline`, **`findingGroups[]`** (same collapse for agents), `rows[]` (per-payload diagnostics), transport flags.

**MCP:** `browser_security_sqli_scan`.

### POST /api/security/ssti-scan
SSTI scan with **unified findings**. Discovers injectable parameters from the network log or an explicit **`request`** template. Arithmetic reflection requires **dual confirm** (49 and 56) for `critical`/`confirmed`. `depth=deep` adds a safe engine canary. Content-Type matrix for POST body markers (skipped in `quick`).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` |
| `request` | — | Optional `{ url, method?, headers?, body? \| json? }` with injection marker |
| `paramName` | — | Parameter name hint for explicit template mode |
| `depth` | `standard` | `quick` \| `standard` \| `deep` |
| `maxCandidates` | from depth | Max network-log injection points |
| `timeoutMs` | `15000` | Per-request timeout |
| `minConfidence` | `likely` | Filter findings |
| `includeHygiene` | `false` | Include non-exploitable tiers |

**Response:** unified envelope; `details.entries[]` has per-candidate rows.

**MCP:** `browser_security_ssti_scan`.

### POST /api/security/ssti-polyglot-scan
**Fast reflected SSTI** probe: single GET **polyglot** payload `${7*7}{{7*7}}<%=7*7%>#{7*7}` across common search/render paths and query parameter names. Baseline diff detects **49** in the response (high) or partial evaluation artifacts like `{{49}}` (medium). Ported from pentest-ai `web.ssti_polyglot`.

**Limitations:** Polyglot is **GET query only** — it will not exercise POST body / Content-Type matrices (e.g. `text/plain` template engines). For those surfaces use **`POST /api/security/ssti-scan`** with an explicit `request` template and the matching Content-Type (often `text/plain` or `application/json`).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max URL paths to try |
| `maxProbes` | `48` | Max path×param probes (each = baseline + attack GET). **`0` = unlimited** (can be slow). |
| `maxParams` | `0` | Max query parameter names per path (`0` = all 9 defaults) |
| `timeoutMs` | `12000` | Per-request timeout |
| `includeScaffold` | `true` | Include built-in paths + `SstiAlwaysProbed` path stems |
| `includeBrowserCookies` | `true` | Merge WebView cookies |
| `paths` | — | Optional explicit path list (e.g. `/search`) |
| `params` | — | Optional query parameter names (default: `q`, `query`, `name`, …) |

**Performance:** Default caps yield ~48 probes (~25–50s). Auto-scan **`scanDepth=standard`** uses **`maxProbes: 24`** and network paths only. Use **`scanDepth=thorough`** or standalone **`maxProbes: 0`** for full cartesian coverage.

**Response:** `message`, `candidatesProbed`, `elapsedMs`, `hasFindings`, `findings[]` (category `ssti-polyglot`, severity, url, paramName, detail, evidence, source).

**MCP:** `browser_security_ssti_polyglot_scan`. In auto-scan: **`includeSstiPolyglot: true`** (default) runs before full SSTI scan; skipped when **`includeSsti: false`**.

### POST /api/security/ssti-stored-scan
**Stored SSTI**: POST template payload to profile-shaped fields (`bio`, `about`, `signature`, …), then **GET readback** URLs for evaluated marker **13289** (`137*97`). Tests Jinja2 `{{137*97}}`, Velocity `${137*97}`, ERB `<%=137*97%>` via form-urlencoded and JSON. Works best when logged in (`includeBrowserCookies`). Ported from pentest-ai `web.ssti_stored`.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `10` | Max profile POST URL candidates |
| `timeoutMs` | `15000` | Per-request timeout |
| `includeScaffold` | `true` | Include built-in profile paths (`/profile/update`, `/api/users/me`, …) |
| `includeBrowserCookies` | `true` | Merge WebView cookies |
| `profileUrls` | — | Optional explicit profile POST URLs |

**Response:** `message`, `candidatesProbed`, `elapsedMs`, `hasFindings`, `findings[]` (category `ssti-stored`, severity, postUrl, readUrl, fieldName, syntax, detail, evidence, source).

**MCP:** `browser_security_ssti_stored_scan`. In auto-scan: **`includeSstiStored: true`** (default); skipped when **`includeSsti: false`**.

### POST /api/security/prototype-pollution-scan
**Server-side prototype pollution**: POST JSON with **`__proto__`** and **`constructor.prototype`** pollution keys, then **GET** verify paths (`/`, `/api/me`, …) for canary strings **`yes-via-proto`** / **`yes-via-ctor`**. Ported from pentest-ai `web.prototype_pollution`.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `10` | Max JSON sink POST URLs |
| `timeoutMs` | `15000` | Per-request timeout |
| `includeScaffold` | `true` | Include built-in paths (`/api/users`, `/api/profile`, …) |
| `includeBrowserCookies` | `true` | Merge WebView cookies |
| `candidateUrls` | — | Optional explicit POST URLs |

**Response:** `message`, `candidatesProbed`, `elapsedMs`, `hasFindings`, `findings[]` (category `prototype-pollution`, severity, postUrl, verifyUrl, canary, detail, source).

**MCP:** `browser_security_prototype_pollution_scan`. In auto-scan: **`includePrototypePollution: true`** (default).

### POST /api/security/csti-scan
**Client-side template injection (CSTI)** scan: navigates the browser with template payloads in URL **query** or **hash** parameters and checks the **rendered DOM** for arithmetic evaluation (**49** from `{{7*7}}`). Complements server-side SSTI — detects AngularJS/Vue/Handlebars client-side compilation sinks.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `url` | current page | Base URL for probes |
| `paramName` | auto | Parameter name (with `url`) or discovery hint |
| `engines` | from tech stack | `angularjs`, `vue`, `handlebars`, `generic` |
| `sources` | both | `url-query`, `url-hash` |
| `escalate` | `false` | Sandbox-escape probes after basic confirmation |
| `monitorSinks` | `true` | Hook eval/Function/innerHTML during probes |
| `maxCandidates` | `10` | Max parameter candidates |
| `timeoutMs` | `10000` | Per-navigation wait |

**Response:** `message`, `candidatesProbed`, `enginesTested`, `elapsedMs`, `hasFindings`, `findings[]` (url, parameter, source, engine, basicExpression, evaluatedToken, codeExecution, sinks, severity), `probes[]`.

**MCP:** `browser_security_csti_scan`.

### POST /api/security/parser-probe
**Parser differential** probe for JSON **POST/PUT/PATCH** endpoints: runs a **Content-Type matrix** (XML, form-urlencoded, multipart valid/missing boundary, java-serialized, text/plain, json utf-7) and **body-shape matrix** (duplicate keys, type confusion, trailing content, json-breaking subset). Flags **`content-type-confusion`**, **`deserialization-suspected`**, **`parser-differential`** for chain analysis.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | Optional explicit `{ url, method?, headers?, body? \| json? }` — else discovers from network log |
| `maxCandidates` | `5` | Max JSON endpoints to probe |
| `includeContentTypeMatrix` | `true` | Run Content-Type swap probes |
| `includeBodyShapeMatrix` | `true` | Run body-shape probes |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `message`, `candidatesProbed`, `probesSent`, `findings[]` (category, severity, signal, url, probeKind, contentType, bodyVariant, baselineStatus, probeStatus, detail).

**MCP:** `browser_security_parser_probe`. In auto-scan: **`includeParserProbe`** omitted = **auto** when JSON POST endpoints exist; `true`/`false` to force.

### POST /api/security/deserialization-scan
**Deserialization scan** for JSON sinks + fixed paths (`/b2b/v2/orders`, `/api/serialize`, …): baseline → **node-serialize** `_$$ND_FUNC$$_` timing → **YAML billion-laughs** DoS; optional **Java** `application/x-java-serialized-object` magic bytes and **PHP** `O:8:"stdClass"` in JSON fields. Categories: **`rce-deserialization`**, **`deserialization-dos`**, **`deserialization-suspected`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max sink endpoints |
| `timeoutMs` | `15000` | Per-request timeout |
| `includeJavaStub` | `true` | Java serialized Content-Type probe |
| `includePhpStub` | `true` | PHP unserialize string probe |
| `includeBrowserCookies` | `true` | Send session cookies |

**MCP:** `browser_security_deserialization_scan`. On by default in auto-scan (`includeDeserializationScan: true`).

### POST /api/security/file-upload-scan
**File upload validation**: baseline PDF → **200 KB oversize** → **`.exe`** wrong-type → **JPEG/PHP polyglot**; SPA shell fingerprint dedup; optional **upload XXE** (multipart `file` + raw `application/xml`). Categories: **`file-upload-oversize`**, **`file-upload-wrong-type`**, **`file-upload-polyglot`**, **`xxe-upload`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `10` | Max upload endpoints |
| `timeoutMs` | `12000` | Per-request timeout |
| `includeXxe` | `true` | Run upload-path XXE probes |
| `tryDomReplayWhenSpaShell` | `false` | Hint `browser_upload` when SPA shell dedup fires |
| `urls` | — | Optional explicit upload URLs |
| `includeBrowserCookies` | `true` | Send session cookies |

**MCP:** `browser_security_file_upload_scan`. On by default in auto-scan (`includeFileUploadScan: true`).

### POST /api/security/nextjs-rsc-scan
**Next.js RSC / Flight deserialization** probe (CVE-2025-66478 class): fingerprint App Router → enumerate action hashes → Flight canary payloads. Category: **`rce-deserialization`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `timeoutMs` | `6000` | Per-request timeout |
| `requireNextJsFingerprint` | `true` | Skip when Next.js not detected |
| `includeBrowserCookies` | `true` | Send session cookies |

**MCP:** `browser_security_nextjs_rsc_scan`. Auto-scan: **`includeNextJsRscScan`** omitted = auto when Next.js detected.

### POST /api/security/race-condition-scan
**Race condition / TOCTOU** — discovers single-use POST endpoints from traffic (submit, redeem, vote, confirm, …), refreshes CSRF from the current page DOM, fires N concurrent identical POSTs, flags when **acceptedCount > 1**. Category: **`race-condition`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max endpoints to burst |
| `burstSize` | `15` | Concurrent requests per burst (total = burstSize + 1) |
| `timeoutMs` | `8000` | Per-request timeout |
| `includeBrowserCookies` | `true` | Send session cookies |
| `includeRedeemCodeBursts` | `true` | Also burst endpoints whose body contains code/coupon/voucher fields |
| `urls` | — | Optional explicit POST URLs |

**Response:** `observations[]` includes `csrf-blocked` when all burst requests fail CSRF validation (inconclusive for race testing). CSRF tokens are scraped via direct DOM query on matching forms (`input[type=hidden][name=csrf]`), not `interactiveElements`. Navigate to the form page before scanning.

**MCP:** `browser_security_race_condition_scan`.

### POST /api/security/captcha-replay-scan
**Broken anti-automation** — detects reCAPTCHA/hCaptcha/Turnstile in DOM (`observations[]` with `captcha-present-untestable`), GET JSON captcha/challenge service → submit twice with same credentials on gated POST endpoints (CSRF refreshed from DOM). Category: **`broken-anti-automation`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxSubmitCandidates` | `6` | Max submit endpoints from traffic |
| `timeoutMs` | `8000` | Per-request timeout |
| `includeBrowserCookies` | `true` | Send session cookies |

**MCP:** `browser_security_captcha_replay_scan`.

### POST /api/security/llm-redteam-scan
**OWASP LLM Top 10 red-team scan** — YAML probe corpus (**29 probes**, LLM01–LLM07), integrated with **Red Team Whisper** (surface hints + finding toasts). Runs via discovered **HTTP adapter** (`openai` / `simple` / `custom`) or **chat UI** (`llm-chat-interact` helper). Optional **WebMCP abuse** probes and **indirect injection** (upload + summarize).

Includes **system-prompt extraction** probes (`llm07_secret_password`, `llm07_initial_instructions`, …) and **output-handling** probes; LLM05 probes in **chat-ui** mode also run a **DOM render check** for unsafe HTML (`<script>`, `onerror=`, etc.) — may fire with `matched: "dom-unsafe-render"`.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `mode` | `auto` | `auto` \| `http` \| `chat` — in `auto`, prefers **chat-ui** when a widget exists and best HTTP endpoint `confidence` &lt; 50; otherwise high-confidence HTTP (`body:llm-json-shape`) over path heuristics |
| `maxProbes` | `24` | Cap probe count |
| `concurrency` | `2` | Parallel probes (HTTP mode only; chat-ui always runs sequentially to avoid DOM conflicts) |
| `timeoutMs` | `30000` | Per-request timeout |
| `probeDelayMs` | `1000` | Delay between probes in chat-ui mode (200–10000 ms). Helps avoid rate limits |
| `includeWebMcpAbuse` | `true` | Curated WebMCP tool argument fuzz after corpus |
| `includeIndirectInjection` | `false` | Upload doc with hidden instruction + summarize |
| `registerWhisperHints` | `true` | Push findings to Red Team Whisper |
| `httpTarget` | — | `{ url, schema, model, headers, useBackendFetch, customBody, customResponseKey }` — `customBody` supports `{{PROMPT}}`, `{PROMPT}`, `§PROMPT§`, `{{MODEL}}` placeholders |
| `chatTarget` | — | `{ inputSelector, submitSelector, responseSelector, waitAfterSubmitMs }` |
| `probeIds` / `categories` | — | Optional filters; unknown IDs/categories returned in `warnings[]`. Alias: `LLM02_Insecure_Output_Handling` → `LLM05_Improper_Output_Handling` |

**Chat-UI response capture** uses a 4-strategy cascade: (1) user-provided `responseSelector` (highest priority), (2) class-based selectors (`.answer`, `.response`, `.assistant-message`, …), (3) structural heuristics (table rows, list items, `[role="log"]` children near the chat input), (4) full-page text diff (compares `document.body.innerText` before/after each probe). This handles table-based, list-based, and unconventional chat layouts. Response isolation extracts only the latest bot message, not the full conversation history.

**Typing indicator filtering:** both JS capture and C# polling detect typing indicators (`[typing...]`, `thinking...`, `loading...`, animated dots, `class="typing"`, `aria-busy="true"`, etc.) and wait through them. The scanner only accepts stable non-typing text. If the deadline expires with only a typing indicator captured, the result is treated as empty (not falsely reported as a real response).

**Dual-channel WebSocket capture:** for pages with active WebSocket connections, frame state is snapshot before each probe submission. If DOM capture fails or returns a typing indicator, new received JSON frames are checked for content fields (`content`, `message`, `response`, …). WebSocket responses appear with `responseSelector: "websocket"`. Supports nested message formats (OpenAI `choices[].message.content`, flat `{ content: "..." }`, etc.).

**Chat-UI resilience:** probes run sequentially; page state is verified before each probe (re-navigates if the page was lost). Rate-limit responses ("too fast", "rate limit", "please wait", …) trigger a 12s back-off + retry.

Response includes `confidence` per probe (`high` | `medium` | `low` | `refused` | **`inconclusive`**). Empty or stale chat responses are **`inconclusive`**, not confident "not fired". Refusal/echo detection avoids firing when the model quotes the probe token without complying.

**MCP:** `browser_security_llm_redteam_scan`.

### GET /api/security/llm-redteam-probes
**Probe catalog** — lists all probe IDs and category names (use for `probeIds` / `categories` filters). Gate-free. REST only (no MCP tool yet).

### GET or POST /api/security/llm-endpoint-discover
**LLM surface discovery** — network log chat/completion APIs, **WebSocket connections** (JSON message pattern analysis for `content`/`message`/`response` keys, user/role indicators, multi-turn patterns), DOM chat widgets, WebMCP tool count, copilot iframes. WebSocket endpoints appear with `source: "websocket"`, `method: "WS"`. Dedupes by URL. Endpoints include `confidence` (0–100). Filters third-party analytics/tracking domains (HubSpot, hsforms, GA, …), static assets (`.gif`, …), and non-JSON/image responses from weak path matches. DOM chat widget discovery detects off-screen inputs (below-fold chat inputs still discovered, with lower confidence). Response area detection probes for table/list/container structure near the chat input. Updates Red Team Whisper `llmSurface`.

POST accepts optional JSON body `{}` (ignored). **Blocked in safe mode.**

**MCP:** `browser_security_llm_endpoint_discover`.

### POST /api/security/llm-chat-interact
**Chat UI helper** — send one prompt through the page chat widget; returns `{ prompt, responseText, responseHtml, inputSelector, responseSelector }`. Uses **lenient DOM interaction** (JS fill/click with shadow-root + same-origin iframe search) — works inside device mockups and Tailwind layouts. **Scroll-first visibility:** automatically scrolls off-screen elements into view before interacting; falls back to DOM-presence check for elements that remain below the fold after scrolling. Auto-detect scores inputs structurally: bottom-of-screen textarea + nearby button, sole visible input, device/mockup containers (no semantic `placeholder`/`aria-*` required). Response capture uses the same 4-strategy cascade as `llm-redteam-scan` (custom selector → class-based → structural heuristics → full-page diff), with latest-response isolation, typing indicator filtering, and WebSocket fallback for dual-channel capture.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `prompt` | — | **Required.** |
| `autoDetect` | `true` | Discover chat selectors when `inputSelector` omitted (top-level or inside `chatTarget`) |
| `chatTarget` | — | `{ inputSelector, submitSelector, responseSelector, waitAfterSubmitMs, autoDetect }` |

**MCP:** `browser_security_llm_chat_interact`.

**Chain-prove:** pattern `llm05-improper-output-handling` → template `llm05-improper-output-handling-proof` (uses workflow `llm-chat` step).

### POST /api/security/rate-limit-audit
**Observational rate-limit audit (A12)** — discovers login, OTP, search, export, coupon, and write API endpoints from traffic; runs sequential baseline (default 5) then small concurrent burst (default 8). Emits **`missing-rate-limit`**, **`weak-rate-limit`**, or **`rate-limit-present`**. Honors HTTP 429 / `Retry-After` when `respectRateLimits` is true (default). POST candidates refresh CSRF from the page/DOM before probing. Login/OTP/coupon endpoints that consistently return 400/401/403/422 without 429 are reported as **`missing-rate-limit`** (rejection without throttling). Static assets and duplicate query-string URLs are filtered during discovery.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max endpoints |
| `sequentialAttempts` | `5` | Sequential requests before burst (max 10) |
| `burstSize` | `8` | Concurrent burst size (max 15) |
| `delayMs` | `200` | Delay between sequential requests |
| `timeoutMs` | `8000` | Per-request timeout |
| `includeBrowserCookies` | `true` | Send session cookies |
| `respectRateLimits` | `true` | Backoff on 429 with Retry-After (max 3 retries) |
| `includeOtpTemplates` | `true` | Wrong OTP payloads on OTP endpoints (max 10 attempts) |
| `registerChainFindings` | `true` | Register for chain-analyze |
| `urls` | — | When set, **only** these URLs are probed (exclusive; network log discovery skipped). User-provided URLs are preserved verbatim in findings and used for probing. Network log is used only for method/body/headers metadata when the path matches. |

**Response:** `rateLimitRespected`, `skippedDueTo429[]`, `backoffEvents`, `findings[]`.

**MCP:** `browser_security_rate_limit_audit`.

### POST /api/security/redos-scan
**ReDoS timing oracle** — one evil-regex payload per injectable search/filter/email parameter (max 3 payloads, sequential). Category: **`redos-suspected`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max injectable endpoints |
| `maxPayloadsPerCandidate` | `3` | Payloads per parameter |
| `slowThresholdSeconds` | `3` | Flag when attack exceeds baseline by this threshold |
| `timeoutMs` | `8000` | Per-request timeout |
| `respectRateLimits` | `true` | Backoff on 429 |
| `registerChainFindings` | `true` | Register for chain-analyze |
| `urls` | — | When set, **only** these URLs are probed (exclusive). |

**MCP:** `browser_security_redos_scan`.

### POST /api/security/body-size-limit-scan
**Body-size limit probe** — escalating tiers 1 KB → 64 KB → 256 KB → 1 MB (one request per tier) on POST endpoints. Categories: **`body-size-unbounded`** (2xx at 1 MB without 413), **`body-size-no-413`** (2xx at intermediate tiers), **`body-size-limit-present`** (HTTP 413). Endpoints that reject all tiers with 4xx (e.g. 400 CSRF, 405 method) are skipped.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `6` | Max POST endpoints |
| `timeoutMs` | `15000` | Per-request timeout |
| `respectRateLimits` | `true` | Backoff on 429 |
| `registerChainFindings` | `true` | Register for chain-analyze |
| `urls` | — | When set, **only** these POST URLs are probed (exclusive). |

**MCP:** `browser_security_body_size_limit_scan`.

### POST /api/security/workflow-skip-scan
**Multi-step workflow bypass** — infers late-stage POST endpoints from traffic (confirm, complete, submit, redeem, …), POSTs directly without earlier steps (CSRF refreshed from DOM); flags 2xx when prerequisites should block. Category: **`workflow-step-skip`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max late-stage endpoints |
| `timeoutMs` | `10000` | Per-request timeout |
| `tryMinimalBody` | `true` | Also try `{}` when captured body is rejected |
| `includeBrowserCookies` | `true` | Send session cookies |
| `urls` | — | Optional explicit POST URLs (bypass late-stage keyword filter) |

**Response:** `properlyGated[]` includes `gateType`: `csrf-validation` or `business-rejection`. CSRF 400s count as properly gated. CSRF tokens are extracted via direct DOM query (`input[type=hidden][name=csrf]`), not `interactiveElements`.

**MCP:** `browser_security_workflow_skip_scan`.

### POST /api/security/cmd-canary
**Command injection / RCE indicator** canaries on injectable string parameters. **Tier A:** error-based (`\`id\``, `$(id)`, `;id`, `|id`); **Tier B:** SSTI arithmetic; **Tier D:** OOB callback (`includeCallback: true`); **Tier E:** timing (`includeTiming: true`). Categories: **`command-injection`**, **`ssti-confirmed`**, **`rce-indicator`**.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | Optional template with **`§INJECT§`** marker |
| `paramName` | — | Parameter name for explicit template |
| `maxCandidates` | `10` | Max injection points from network log |
| `includeSstiTier` | `true` | Include SSTI arithmetic tier |
| `includeCallback` | `false` | OOB callback tier (uses `CallbackDetector`) |
| `includeTiming` | `false` | Timing tier (sleep payloads) |
| `timingThresholdMs` | `3500` | Min delta vs baseline for timing finding |
| `callbackWaitMs` | `2000` | Wait after probes for callback hits |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `message`, `candidatesProbed`, `payloadsSent`, `findings[]` (category, tier, paramName, payload, indicator, detail).

**MCP:** `browser_security_cmd_canary`. Optional in auto-scan: **`includeCmdCanary: false`** to skip.

### POST /api/security/js-audit
Heuristic scan of **external `script[src]`** bundles: collects URLs from the live DOM, **GET**s each script (server-side `HttpClient`, size-capped) and flags **credential-like** assignments (`password=…`, `apiKey=…`, etc.), **internal / private** URLs, **email near secret-like** substrings, and common **debug / test** markers (e.g. `testingPassword`, `ng.probe`, `localhost`). Complements `POST /api/security/source-maps` (framework debug), which does not read `main.js` content for static secrets. Does **not** follow dynamic `import()`. Truncation note per file if `maxBytesPerFile` is exceeded.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxScripts` | `32` | Max distinct script URLs to fetch (capped, max 80) |
| `maxBytesPerFile` | `524288` | Max bytes read per script (capped) |
| `sameOriginOnly` | `false` | If `true`, only `script[src]` on the same host as the page |
| `timeoutMs` | `20000` | Per-GET timeout |

**Response:** `scriptsDiscovered`, `scriptsFetched`, `summary[]`, `assets[]` (`url`, `byteLength`, `error?`, `hits[]` with `category`, `pattern`, `offset`, `snippet`).

**MCP:** `browser_security_js_audit`.

### POST /api/security/jwt-analyze
Reads **cookies, localStorage, and sessionStorage** via one in-page script; finds JWT-shaped strings; Base64url-decodes header/payload (no signing or forgery). **Optional** **`token`** (string) and **`tokens`** (array) decode JWTs you already have (e.g. from `POST /api/fetch` or a login response) in addition to page-derived tokens. Reports `alg`, optional `exp`, sensitive claim names, and static notes for **`none` / HS256 / RS256** (e.g. algorithm-confusion hygiene).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `token` | — | Optional. Single raw JWT to analyze (merged with matches from cookies/storage) |
| `tokens` | — | Optional. Array of JWT strings (merged with `token` and page-derived list) |

**Response:** `count`, `tokens[]`, and **`findings[]`** (same array as `tokens` for tool compatibility) — each item: `source`, `raw` (truncated), `algorithm`, `header`, `payload`, `issues`, `sensitiveClaims`, `expiresUtc`.

**MCP:** `browser_security_jwt_analyze` (same parameters: `token`, `tokens`).

### POST /api/security/jwt-forge
Pure **JWT (JWS) manipulation** for security testing: decode `baseToken`, apply **`modifications`** to header/payload JSON, re-encode Base64url, optionally **`stripSignature: true`** (emit `header.payload.`). Supports nested keys via **`header.*`** / **`payload.*`** dot paths (e.g. `payload.data.email`) plus shallow **`header`** / **`payload`** object merges. **Does not** re-sign HS256/RS256 — changing claims invalidates the original signature unless you strip it (e.g. `alg: none` acceptance tests). Returns `token`, decoded `header` / `payload` strings, `signatureStripped`, and `notes`.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `baseToken` | — | **Required.** Existing JWT (`header.payload.sig` or empty `sig`) |
| `modifications` | — | Optional object: `header`, `payload`, `header.alg`, `payload.role`, … |
| `stripSignature` | `false` | Clear signature segment (typical with unsigned / `none` flows) |

**MCP:** `browser_security_jwt_forge`.

### POST /api/security/jwt-acceptance-sweep
Cookie-isolated sweep of attack-surface endpoints for **missing authentication** and **JWT alg:none acceptance** (anonymous GET vs Bearer alg:none). Requires browse first for attack-surface data.

`MISSING_AUTH` requires response body to look like **authenticated/sensitive content** — HTTP 200 login pages (password fields, sign-in text) are **not** flagged (avoids false positives on Java/JSP apps that redirect to login with 200).

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_jwt_acceptance_sweep`.

| Field | Default | Description |
|-------|---------|-------------|
| `token` / `baseToken` | — | Explicit JWT or Bearer token (alg:none accepted as-is) |
| `host` | — | Limit to host |
| `maxEndpoints` | 15 | Cap endpoints tested |
| `verbose` | false | Include `jwtPayloadUsed` per row |
| `includeUnauthenticatedOnly` | false | Skip JWT tests when no token |

**Response:** `rows[]` (one per endpoint: `NO_ISSUE`, `MISSING_AUTH`, `JWT_ALG_NONE`), `summary[]`, `endpointsTested`, `jwtSource`, `authContext` (cookie-based auth hint when no JWT).

### POST /api/security/auth-bypass-pivot
Captures a token (explicit, session JWT analyze, cookie session, or SQLi login bypass) and retests endpoints that reject anonymous callers (401/403 from network log + attack-surface). Emits `AUTH_BYPASS_PIVOT` rows; chain category `auth-bypass-pivot`.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_auth_bypass_pivot`. Auto-scan: `includeAuthBypassPivot: true`.

| Field | Default | Description |
|-------|---------|-------------|
| `token` | — | Bearer JWT, raw token, or session cookie value |
| `authMode` | auto | `bearer`, `cookie`, or `auto` |
| `cookieName` | — | Cookie header name when `authMode: cookie` |
| `loginUrl` | — | Login URL for SQLi bypass |
| `trySqliLoginBypass` | true | Attempt SQLi payloads when no token |
| `maxEndpoints` | 20 | Cap retest targets |

**Response:** `rows[]` with `outcome` (`UNLOCKED` \| `STILL_DENIED` \| `ANON_ALREADY_OK`), `endpointsRetested`, `endpointsUnlocked`, `tokenSource`, `tokenType`, `sqliAttempts[]`.

### POST /api/security/rest-scaffold
Probes common REST collection paths (`/api/Users`, `/rest/admin/…`, etc.) without authentication. Auto-scan runs when captured API endpoints &lt; `restScaffoldSparseThreshold` (default 3).

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_rest_scaffold`.

| Field | Default | Description |
|-------|---------|-------------|
| `paths` | built-in ~20 | Custom path list to probe |
| `includeHead` | true | Also probe with HEAD |
| `maxPaths` | 24 | Cap paths |

**Response:** `pathsProbed[]`, `rows[]` per path/method (`result`: leak \| protected \| not_found \| empty), `findings[]` for actual leaks.

### POST /api/security/path-filter-bypass
NUL-byte, double-encoding, and backslash-normalization bypass probes on directory bases. Compares bypass responses against site root to suppress `..` → `/` false positives.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_path_filter_bypass`. Auto-scan: `includePathFilterBypass: true`.

| Field | Default | Description |
|-------|---------|-------------|
| `bases` / `pathBases` | `/admin/`, `/api/`, … | Directory bases to probe |
| `basePath` | current page origin | Site root for comparison |
| `maxBases` | 8 | Cap bases |

**Response:** `basesUsed[]`, `findings[]` with verified indicators (directory-listing content check).

### POST /api/security/harvest-ids
Harvest numeric/GUID/hex IDs from network log + DOM; returns **`suggestedBoundaryTests`** for `authz/boundary`. Read-only — no `safetyMode` required.

**MCP:** `browser_security_harvest_ids`.

**Response:** `ids[]` with `type`, `paramName`, `source` (`query-param`, `network-path`, `dom`), `contextUrl` (request URL, not data URIs), `sequential` flag; `suggestedBoundaryTests[]` for IDOR boundary probes.

### POST /api/security/brute-force
Sends **N sequential** failed login attempts (wrong password) to measure **lockout / rate-limit** signals, or **password spray** mode when **`usernames[]`** is set (one password across many accounts). **Cap:** 50 attempts (single-user) or 25 usernames (spray).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `loginUrl` or `url` | — | Login endpoint |
| `method` | `POST` | HTTP method |
| `headers` | — | Optional header map |
| `body` or `json` | — | Template; replace **`passwordPlaceholder`** / **`usernamePlaceholder`** |
| `passwordPlaceholder` | `{{PASSWORD}}` | Literal substring replaced with password |
| `usernamePlaceholder` | `{{USERNAME}}` | Literal substring replaced in spray mode |
| `wrongPassword` | random | Fixed wrong password (single-user mode) |
| `usernames` | — | **Spray mode:** array of usernames (max 25); uses one password per round |
| `passwords` | — | Optional spray passwords (rotates); default built-in list when omitted |
| `attempts` | `6` | 1–50 (single-user mode only) |
| `delayMs` | `75` | Pause between attempts (spray: clamped 50–2000 ms) |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `lockoutOrRateLimitSuspected`, `sprayMode`, `perUserLockoutSuspected`, `successCount`, `observations[]`, `attempts[]` (single-user) or `sprayRows[]` (username, status, successSuspected, …).

**MCP:** `browser_security_brute_force`.

### POST /api/security/session-fixation-scan
Detects **session fixation** — captures session cookie before login, authenticates, flags unchanged session ID. Category: **`session-fixation`**. Chain-prove: `session-fixation-proof`.

Auto-detects form logins from the page DOM (`input[type=password]` + adjacent text field) and infers form-urlencoded bodies (e.g. testfire `uid`/`passw` on `/doLogin`). **Primary login path uses browser form submit** (navigate → fill DOM fields → submit) so CSRF tokens, hidden fields, and multi-step flows work; raw HTTP POST is fallback only.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_session_fixation_scan`.

| Field | Default | Description |
|-------|---------|-------------|
| `loginUrl` | auto | Login URL (enriched from page/network when set) |
| `username` / `password` | — | Optional credentials; else tries `admin`/`admin` and domain-based defaults |
| `usernameField` / `passwordField` | auto | Form field names (e.g. `uid`, `passw`) — auto-builds HTTP body; also guides browser fill |
| `contentType` | auto | `application/x-www-form-urlencoded` or `application/json` (HTTP fallback) |
| `body` | auto | Login body template with `§USER§` / `§PASS§` placeholders (HTTP fallback) |
| `preferBrowserLogin` | `true` | Use browser DOM login first; set `false` to force HTTP-only |
| `cookieName` | — | Filter to one session cookie name |
| `tryDefaultCredentials` | `true` | Try built-in default pairs when username omitted |
| `timeoutMs` | `15000` | Per-request timeout |

### POST /api/security/password-reset-weak-scan
Weak **security-question password reset** — fetch question, try canonical answers, optionally change password. Category: **`password-reset-weak`**. Gate: **`confirmDestructive: true`** to POST reset.

Default test email is **`admin@{host}`** when `email` is omitted (derived from current page host).

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_password_reset_weak_scan`.

| Field | Default | Description |
|-------|---------|-------------|
| `email` | `admin@{host}` | Target email for question/reset probes |
| `questionUrl` / `resetUrl` | auto | Override discovered URLs |
| `confirmDestructive` | `false` | Allow password change POST |
| `timeoutMs` | `15000` | Per-request timeout |

### POST /api/security/account-enumeration-scan
**Account enumeration** — REST user-list leak (network-discovered `/api/users` paths + scaffold), login valid/invalid differential (status/length/timing/message), registration duplicate-email messages. Category: **`account-enumeration`**.

Uses same form-login enrichment as session-fixation-scan. Gracefully handles missing/empty `Content-Type` on login requests.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_account_enumeration_scan`.

| Field | Default | Description |
|-------|---------|-------------|
| `loginUrl` | auto | Login URL for differential probe |
| `validUsername` | `admin@{host}` | Known-valid username for differential probe |
| `usernameField` / `passwordField` | auto | Form field names |
| `contentType` / `body` | auto | Login request format |
| `registerUrl` | auto | Registration URL for duplicate-email probe |
| `includeRestLeak` | `true` | Probe user-list REST paths |
| `includeLoginDifferential` | `true` | Compare valid vs invalid login responses |
| `includeRegisterProbe` | `true` | Probe registration duplicate messages |
| `maxRestPaths` | `12` | Max user-list paths to probe |
| `timeoutMs` | `15000` | Per-request timeout |

### POST /api/security/logout-invalidation-probe
**Logout invalidation** — call logout, replay protected URL with pre-logout cookie; flags **`SESSION_STILL_VALID`**. Detects session invalidation when post-logout response is a **login page** (HTTP 200 + password field), not only 401/403. Browse while logged in first.

Auto-detect prefers **current page** (when authenticated), **Sign Off/Logout links**, network history, then hints (`/logout.jsp`, `/bank/main.jsp`).

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_logout_invalidation_probe`.

| Field | Default | Description |
|-------|---------|-------------|
| `logoutUrl` | auto | Logout URL |
| `protectedUrl` | auto | Authenticated page/API to replay after logout |
| `timeoutMs` | `15000` | Per-request timeout |

### POST /api/security/idor-scan
Fetches a template with **exactly one** `§id§` or `{{id}}` marker for multiple **id** values; compares **status**, **length**, and a short **body fingerprint** (heuristic IDOR / inconsistent authorization). By default **`inferMethodsFromNetwork`** matches the session **network log** (same host + path prefix as the template URL with markers stripped) and adds observed methods.

**Destructive behavior:** **`includeMutatingProbes`** defaults to **`false`**. When **`true`**, Trowser also sends **PUT**, **PATCH**, and **DELETE** against the same URL template — these can **modify or delete real resources** (e.g. `DELETE /api/room/1`). Prefer **`dryRun: true`** to list planned requests without sending them; use **`safeDefaults: true`** or start Trowser with **`--safe-probes-only`** for read-only probes only. Pass **`readOnlyProbes: true`** to restrict to **GET** / **HEAD** / **OPTIONS**. **`--dangerous-ok`** restores legacy omission behavior (mutating probes when the JSON omits `includeMutatingProbes`). JSON bodies use the same marker substitution as SQLi (string values only).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | **`{ url, method?, headers?, body? \| json? }`** — exactly one id marker |
| `ids` | `["1","2","999999","0"]` | Strings to substitute (if omitted or empty, uses default list) |
| `timeoutMs` | `15000` | Per-request timeout |
| `methods` | *(omit)* | If set, **only** these HTTP methods are used (skips network inference and mutating fallbacks) |
| `inferMethodsFromNetwork` | `true` | Add methods seen in the capture log for the same API path |
| `includeMutatingProbes` | `false` | Also probe **PUT**, **PATCH**, **DELETE** (**destructive** — can change/delete data) |
| `readOnlyProbes` | `false` | Only **GET** / **HEAD** / **OPTIONS** (forced **`true`** with `safeDefaults` or `--safe-probes-only`) |
| `safeDefaults` | `false` | Mutating IDOR off + read-only verbs |
| `dryRun` | `false` | Return **`plannedRequests`** only — **no HTTP executed** |

**Response:** `warnings[]` (prominent risk notes), `dryRun`, `plannedRequests` (when dry-run), `summary[]`, `rows[]` (id, **method**, url, status, bodyLength, fingerprint).

**MCP:** `browser_security_idor_scan`.

### POST /api/security/mass-assignment-scan
Heuristic **JSON mass assignment** probe (OWASP API / broken object property level authorization): sends a **baseline** `fetch` with the given JSON, then **one request per candidate field** with an extra property merged in (`role`→`"admin"`, numeric `UserId`→`2`, `balance`→`999999.99`, etc.). **Candidate fields** = optional **`privilegedFields`** plus keys from request/response that match built-in patterns (`role`, `UserId`, `balance`, …). Flags **`valueReflected`** when the JSON response contains the injected value for that field.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | **`{ url, method?, headers?, json? \| body? }`** — **JSON object** string (required) |
| `privilegedFields` | *(optional)* | Extra field names to inject (e.g. `["role","isAdmin","UserId"]`) |
| `verifyPersistence` | `false` | Re-fetch resource after inject; set **`valuePersisted`** when field sticks |
| `verifyFetchUrl` | same as request.url | GET (or custom method) URL for persistence check |
| `verifyFetchMethod` | `GET` | Method for persistence check |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `baselineStatus`, `baselineBodySample`, `fieldsTested[]`, `summary[]`, `probes[]` (field, injectedValue, status, valueReflected, **valuePersisted**, verifyFetchUrl, bodySnippet).

**MCP:** `browser_security_mass_assignment_scan`.

### POST /api/security/mass-assignment-patch
**PATCH/PUT self-promote** probe (pentest-ai `privilege_escalation_patch` style): discovers profile update endpoints from traffic, injects privileged fields (`role`, `isAdmin`, `balance`, …), then **verifies persistence** via GET `/api/users/me` (or discovered me URL).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `timeoutMs` | `15000` | Per-request timeout |
| `maxFields` | `8` | Max privileged fields to test |

**Response:** `userId`, `meUrl`, `probes[]` (url, method, field, injectedValue, updateStatus, valuePersisted, verifyUrl, severity), `summary[]`.

**MCP:** `browser_security_mass_assignment_patch`.

### POST /api/security/mass-assignment-register
**Registration mass-assignment** scaffold: probes signup/register paths with extra privileged fields. **Creates real user accounts.**

**Safety gate:** `"safetyMode": "active"` **and** `"confirmDestructive": true`. **Blocked in safe mode.** Skipped by `safeDefaults` / `--safe-probes-only` in auto-scan.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `confirmDestructive` | — | **Required.** |
| `timeoutMs` | `15000` | Per-request timeout |
| `maxPaths` | `6` | Max registration paths |
| `paths` | *(discovered)* | Optional explicit paths |

**MCP:** `browser_security_mass_assignment_register`.

### POST /api/security/bfla-probe
**Broken Function Level Authorization** probe: sends **POST/PUT** to admin paths using the **current session** cookies. Discovers admin endpoints from attack surface + built-in admin path list.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `baseUrl` | *(page origin)* | Optional base URL |
| `host` | *(all)* | Filter attack-surface discovery |
| `timeoutMs` | `12000` | Per-request timeout |
| `maxEndpoints` | `12` | Max admin endpoints |
| `adminPaths` | *(built-in)* | Optional admin path prefixes |
| `discoverFromAttackSurface` | `true` | Merge endpoints from network log |

**MCP:** `browser_security_bfla_probe`.

### POST /api/security/response-field-diff
**Excessive data exposure** probe: compares JSON field paths between **two captured identities** on the same endpoints. Flags fields present for the low-privilege identity that may be admin-only.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.** Capture identities first with `POST /api/identity/capture`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `lowPrivilegeIdentity` | — | Captured identity name (alias: `userIdentity`) |
| `highPrivilegeIdentity` | — | Captured identity name (alias: `adminIdentity`) |
| `host` | *(all)* | Filter attack-surface discovery |
| `endpoints` | *(discovered)* | Optional explicit URLs |
| `maxEndpoints` | `10` | Max endpoints to compare |
| `timeoutMs` | `15000` | Per-request timeout |
| `discoverFromAttackSurface` | `true` | Use network log endpoints |

**MCP:** `browser_security_response_field_diff`.

### POST /api/authz/role-matrix
**Authorization role matrix**: fetches endpoints as each captured identity and classifies access (`allowed`, `denied`, `error`, `same-as-admin`). Highlights endpoints where a low-privilege identity receives the same response as admin.

Requires **`identities`**: array of at least two captured identity names. **Allowed in safe mode** (read-only GET fetches with swapped cookies).

| Field | Default | Description |
|-------|---------|-------------|
| `identities` | — | **Required.** e.g. `["user", "admin"]` |
| `host` | *(all)* | Filter attack-surface discovery |
| `endpoints` | *(discovered)* | Optional explicit endpoints |
| `includeAdminEndpoints` | `true` | Include admin paths from attack surface |
| `maxEndpoints` | `20` | Max endpoints in matrix |
| `timeoutMs` | `15000` | Per-request timeout |
| `discoverFromAttackSurface` | `true` | Use network log endpoints |

**MCP:** `browser_authz_role_matrix`.

### POST /api/security/auto-scan
Automated scan pipeline: derives endpoints from captured traffic, then **`includeApiEnrichment` (default `true`)** merges OpenAPI/JS bundle hints like `attack-surface`, then runs **SQLi**, **SSTI** (micro-scanner + polyglot + stored), **CSTI**, **NoSQL**, **LDAP**, **sqli-login-sweep**, **prototype pollution**, **cmd-canary**, **IDOR**, **CSRF**, **path-traversal**, **SSRF**, **open-redirect**, **mass-assignment**, and optional **parser-probe / deserialization / file-upload / Next.js RSC**. When attack-surface endpoint count is below **`sparseInjectionThreshold`**, also runs **ALWAYS_PROBED** scaffold templates for **SQLi** and **SSTI**. Emits a **preflight warning** when the network log is navigation-only (no XHR/fetch or form POST interaction captured). Selects scanner-appropriate endpoints (e.g. SQLi for endpoints with query/body params; SSRF for URL-like params; **open-redirect for redirect-like params or 302 response patterns**; IDOR for path params **or inferred** REST collection URLs such as `/api/items` → `/api/items/{id}`). Returns a **prioritized findings list** sorted by severity.

**IDOR safety:** **`includeIdorMutatingProbes`** defaults to **`false`** (no PUT/PATCH/DELETE for IDOR). Use **`safeDefaults: true`** to force read-only IDOR verbs and **skip mass-assignment**, or **`--safe-probes-only`** at startup (overrides JSON for those probes).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `scanDepth` | `"standard"` | Scan breadth: **`quick`** (skip polyglot, tighter caps), **`standard`** (balanced — polyglot capped at 24 probes), **`thorough`** (full polyglot scaffold + higher limits). Aliases: `fast`/`light`, `normal`/`balanced`, `deep`/`full`. |
| `maxStepSeconds` | depth default | Hard wall-clock budget. Defaults: **quick=120**, **standard=300**, **thorough=900**. On expiry the scan returns **partial results** (`budgetExhausted: true`) instead of hanging the busy gate. Set explicitly to override; playbook budgets still win when tighter. |
| `host` | *(all)* | Filter endpoints to a specific host (hostname, `host:port`, or origin/URL — same rules as attack-surface) |
| `maxEndpointsPerScanner` | `5` | Max endpoints each scanner tests |
| `timeoutMs` | `15000` | Per-request timeout |
| `includeSqli` | `true` | Run SQL injection scanner |
| `includeIdor` | `true` | Run IDOR scanner |
| `includeCsrf` | `true` | Run CSRF scanner |
| `includePathTraversal` | `true` | Run path traversal scanner |
| `includeSsrf` | `true` | Run SSRF scanner on URL-like parameters |
| `includeOpenRedirect` | `true` | Run open redirect scanner on redirect/url/next parameters |
| `includeSsti` | `true` | Run SSTI micro-scanner (`{{7*7}}`, `${7*7}`, template errors) on traffic-derived params |
| `includeSstiPolyglot` | `true` | Run fast GET polyglot SSTI probe (before full SSTI; **skipped when `scanDepth=quick`**; **capped at 24 probes** when `standard`) |
| `includeSstiStored` | `true` | Run stored SSTI profile POST+GET probe (requires `includeSsti`) |
| `includeCsti` | auto | Run CSTI DOM scan (`{{7*7}}` in URL query/hash). Omit = auto when AngularJS/Vue/Handlebars detected; `true` = force; `false` = skip |
| `includeParserProbe` | auto | Run parser-probe when JSON POST endpoints exist (`true`/`false` to force) |
| `includeDeserializationScan` | `true` | Run deserialization-scan (node-serialize + YAML DoS) |
| `includeFileUploadScan` | `true` | Run file-upload-scan (+ upload XXE) |
| `includeNextJsRscScan` | auto | Run nextjs-rsc-scan when Next.js detected |
| `includeCmdCanary` | `true` | Run cmd-canary on injectable params (error/SSTI/OOB/timing tiers) |
| `includeNosql` | `true` | Run NoSQL operator injection scan on login/search endpoints |
| `includeLdap` | `true` | Run LDAP filter injection scan on login endpoints |
| `includeSqliLoginSweep` | `true` | Run SQLi login bypass sweep on common login paths |
| `includePrototypePollution` | `true` | Run server-side prototype pollution POST+GET verify |
| `sparseInjectionThreshold` | `3` | When attack-surface endpoints &lt; this, also probe ALWAYS_PROBED SQLi/SSTI URL templates |
| `includeApiEnrichment` | `true` | Merge OpenAPI/JS hints before scanning |
| `includeMassAssignment` | `true` | Run mass assignment scanner |
| `includeMassAssignmentPatch` | `false` | Run PATCH/PUT self-promote probe (destructive) |
| `includeMassAssignmentRegister` | `false` | Run registration mass-assignment scaffold (destructive; requires `confirmDestructive` at REST) |
| `includeBflaAdminProbe` | `true` | Run BFLA admin POST/PUT probe |
| `includeIdorMutatingProbes` | `false`* | IDOR: also **PUT**/**PATCH**/**DELETE** (*`true` if started with **`--dangerous-ok`** and property omitted) |
| `idorReadOnlyProbes` | `false` | IDOR: only GET/HEAD/OPTIONS |
| `safeDefaults` | `false` | Read-only IDOR + skip mass-assignment |
| `minPriority` | `"low"` | Minimum endpoint priority to scan: `low`, `medium`, `high`, `critical` |
| `findingsMode` | `"append"` | **`append`** merges into chain-findings feed; **`replace`** clears prior auto-scan findings |
| `includeJwtAcceptanceSweep` | auto | JWT alg:none sweep when attack-surface marks endpoints authenticated; omit = auto-detect; `true`/`false` to force |
| `includeRestScaffold` | `false` | Force REST scaffold probe |
| `includeAuthBypassPivot` | `false` | Run auth-bypass-pivot after weak-auth signals |

**Response:** `warnings[]`, **`scanDepth`** (applied profile: `quick` | `standard` | `thorough`), **`maxStepSeconds`** (applied budget), **`budgetExhausted`** / **`partial`** (true when the step budget cut the run short — findings already collected are still returned), `endpointsDiscovered`, `endpointsScanned`, `scannersRun[]`, `scannersSkipped[]`, `findingsCount`, `findings[]` (scanner, severity, endpoint, method, title, detail, optional `occurrences` when deduped, optional `nextActions[]` verify-workflow stubs), `attackSurfaceSummary`, `errors[]`, `elapsedMs`.

**MCP:** `browser_security_auto_scan`.

### POST /api/security/secrets-harvest
Unified **secret/credential harvesting** across all browser sources in one call: **JS bundles** (hardcoded credentials, API keys, internal URLs via `js-audit`), **cookies & storage** (JWT tokens, auth tokens, PII via `jwt-analyze` + `storage` audit), **network responses** (leaked credentials, bearer tokens, password hashes in response bodies), **network request headers** (Bearer tokens, API keys in `Authorization`, `X-Api-Key`, `X-Auth-Token` headers — category `api-key-in-request`), **visible page text** (debug output, exposed secrets), and **source maps** (exposed `.map` files, debug mode indicators). Returns **deduplicated**, **severity-prioritized** findings. Includes **false positive suppression** for known library patterns (e.g. lodash FP alias mappings).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `includeJsBundles` | `true` | Scan JS `script[src]` assets for hardcoded secrets |
| `includeCookiesAndStorage` | `true` | Analyze cookies, localStorage, sessionStorage for tokens/PII |
| `includeNetworkResponses` | `true` | Scan captured network response bodies for credential exposure |
| `includePageText` | `true` | Scan visible page text for secrets/debug output |
| `includeSourceMaps` | `true` | Check for exposed source maps and debug mode |
| `maxJsScripts` | `20` | Max JS scripts to fetch and scan |
| `maxNetworkResponses` | `100` | Max network response bodies to scan |
| `maxBytesPerFile` | `1048576` | Max bytes read per JS bundle |
| `includeHtmlComments` | `true` | Scan HTML comments in page source |
| `timeoutMs` | `30000` | Timeout for JS bundle fetches |

**Response:** `url`, `totalFindings`, `findings[]` (source, category, severity, location, description, snippet), `warnings[]` (e.g. large-bundle truncation — not counted as secrets), `summary` (critical, high, medium, low, info, bySource, byCategory), `sourcesScanned[]`, `errors[]`, `elapsedMs`. Detects emails, Luhn-valid credit cards, PEM private keys, JWTs, API keys, and comment-embedded secrets.

**MCP:** `browser_security_secrets_harvest`.

### POST /api/security/oidc-analyze
**OIDC provider security analysis.** Fetches `.well-known/openid-configuration` from the specified issuer (or auto-detects from network traffic) and performs comprehensive security checks:

- **Grant types:** flags `implicit` (HIGH) and `password`/ROPC (HIGH) as deprecated/dangerous
- **Grant type live probing** (`testGrantTypes: true`): POSTs to the token endpoint with detected client IDs and dangerous grant types (`password`, `client_credentials`). Distinguishes `unauthorized_client` (client blocked — INFO) from `invalid_grant` (grant accepted, creds wrong — CRITICAL for password, HIGH for client_credentials). Auto-detects client IDs from authorize URLs, token request bodies, and JWT `aud`/`azp` claims.
- **PKCE:** flags `plain` method (HIGH), missing S256 (MEDIUM), no PKCE advertised (MEDIUM)
- **Scopes:** categorizes all scopes (admin, financial, user-data, standard, other); flags admin/financial scopes (MEDIUM)
- **Signing algorithms:** flags `none` (CRITICAL), symmetric HS* (MEDIUM); reports full algorithm inventory
- **ACR values:** flags test/mock/bypass authenticators (HIGH); reports low-assurance levels
- **Dynamic Client Registration:** probes registration endpoint; flags open (unauthenticated) registration (HIGH)
- **Endpoint probes:** tests reachability of authorization, token, userinfo, JWKS, introspection, revocation, end_session, device_authorization, PAR endpoints
- **JWKS analysis:** key count, types, algorithms; flags weak RSA keys (< 2048 bits)
- **Misconfiguration:** HTTP endpoints (CRITICAL), issuer mismatch (HIGH), request_uri SSRF risk (MEDIUM)

**Auto-detection** (when `issuer` is omitted): scans network log for `.well-known/openid-configuration` fetches, JWT `iss` claims in Bearer tokens, and `/authorize` URLs with `client_id` parameters.

| Field | Default | Description |
|-------|---------|-------------|
| `issuer` | auto-detect | OIDC issuer URL (e.g. `https://login.example.com/realms/myrealm`) |
| `autoDetect` | `true` | Auto-detect issuer from network traffic |
| `probeEndpoints` | `true` | Probe all discovered endpoints for reachability |
| `testDynamicRegistration` | `true` | Test if dynamic client registration is open |
| `testGrantTypes` | `false` | Actively probe token endpoint with detected client IDs to verify if dangerous grant types are usable |
| `clientId` | auto-detect | Explicit client_id to test. If omitted, auto-detected from network log |
| `timeoutMs` | `20000` | HTTP request timeout |

**Response:** `issuer`, `configurationUrl`, `configurationFound`, `totalFindings`, `findings[]` (category, severity, title, description, recommendation, detail), `summary` (critical, high, medium, low, info, grantTypesSupported, scopesSupported, signingAlgorithms, endpointsDiscovered), `endpointProbes[]` (name, url, reachable, statusCode, error), `grantTypeProbes[]` (grantType, clientId, tokenEndpoint, statusCode, errorCode, errorDescription, verdict, error — when `testGrantTypes` is true), `errors[]`, `elapsedMs`.

**MCP:** `browser_security_oidc_analyze`.

### POST /api/security/oauth-flow-test
**OAuth2/OIDC authorization-flow security testing** — complements `oidc-analyze` (static provider config) with front-channel flow analysis and active manipulation probes.

**Passive analysis** (always runs; no `safetyMode: "active"` needed when `passiveOnly: true`):
- Parses `/authorize` and callback URLs from the network log (or `authorizationUrl`)
- Flags missing/weak `state`, missing PKCE, `code_challenge_method=plain`, implicit `response_type=token`
- Detects tokens in URL fragment, mix-up indicators (multiple issuers/clients), Referer leakage of OAuth params
- Optional `checkBrowserLeaks`: `window.opener`, `document.referrer`, `location.hash` on the current page

**Active probes** (require `safetyMode: "active"`, skipped when `passiveOnly: true`):
- `redirect_uri` manipulation (evil.com, subdomain/suffix/scheme attacks)
- State removal and fixed-state acceptance
- PKCE stripped / `plain` method
- Scope escalation (admin, offline_access, etc.)
- Implicit flow downgrade (`response_type=token`)
- Token exchange with forged authorization code

Uses browser `fetch` with `redirect: "manual"` (server-side fallback with session cookies) for redirect chain analysis.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | `"active"` required for active probes. (`confirmBackend: true` accepted as legacy alias) |
| `passiveOnly` | `false` | Network-log + browser leak analysis only |
| `authorizationUrl` | auto-detect | Baseline authorize URL from network log |
| `tokenEndpoint` | auto-detect | Token endpoint |
| `clientId` | auto-detect | OAuth client_id |
| `redirectUri` | auto-detect | Registered redirect_uri |
| `issuer` | — | Build authorize URL from `.well-known` when no traffic captured |
| `autoDetect` | `true` | Parse network log |
| `checkBrowserLeaks` | `true` | Inspect opener/referrer/hash on current page |
| `skipRedirectUriTests` | `false` | Skip redirect_uri probes |
| `skipStateTests` | `false` | Skip state probes |
| `skipPkceTests` | `false` | Skip PKCE probes |
| `skipScopeTests` | `false` | Skip scope escalation |
| `skipResponseTypeTests` | `false` | Skip implicit downgrade |
| `skipTokenExchange` | `false` | Skip stolen-code token POST |
| `timeoutMs` | `15000` | Per-probe timeout |

**Response:** `flowsCaptured`, `capturedFlows[]`, `totalFindings`, `findings[]`, `probes[]` (test, url, statusCode, location, verdict, notes), `summary`, `errors[]`, `elapsedMs`.

**MCP:** `browser_security_oauth_flow_test`.

### POST /api/security/graphql-analyze
**Automated GraphQL endpoint security analysis.** Performs 9 checks in a single call:

1. **Introspection test** — Full schema introspection, type inventory, sensitive type detection (user, admin, password, token, secret, payment, credential, auth, session, key, private, internal, role, permission)
2. **Mutation/subscription discovery** — Reports whether mutations or subscriptions exist (write access = critical finding)
3. **Query batching** — Sends array of queries to detect batch support (rate limit bypass)
4. **Alias amplification** — Sends 10+ aliases, measures response size, detects missing complexity limits
5. **Depth limit probe** — Tests nested queries at depth 3, 5, 8, 10, 15 to find the depth ceiling
6. **Max limit test** — Tests collection `limit`/`first` parameter with 100, 1000, 10000 to find upper bound
7. **Draft/preview access** — Tests `preview: true` parameter and `?preview=true` URL parameter (Contentful-style)
8. **Field suggestion exploitation** — Sends invalid field name, checks if error messages suggest valid fields (schema enumeration without introspection)
9. **Rate limit extraction** — Reports rate limit headers from all responses

**Auto-detection** (when `url` is omitted): scans network log for POST requests to URLs containing "graphql" or requests with `application/graphql` content type.

**Safety gate:** Requires `"safetyMode": "active"` — sends probing queries to the target endpoint.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | required | `"active"` — confirm sending probing queries to the target endpoint. (`confirmBackend: true` accepted as legacy alias) |
| `url` | auto-detect | GraphQL endpoint URL |
| `headers` | `{}` | HTTP headers to include (e.g. `{"Authorization": "Bearer ..."}`) |
| `autoDetect` | `true` | Auto-detect GraphQL URL from network traffic |
| `timeoutMs` | `30000` | Overall timeout |
| `skipIntrospection` | `false` | Skip introspection test |
| `skipBatching` | `false` | Skip query batching test |
| `skipAmplification` | `false` | Skip alias amplification test |
| `skipDepthProbe` | `false` | Skip depth limit probe |
| `skipLimitProbe` | `false` | Skip max limit test |
| `skipFieldSuggestion` | `false` | Skip field suggestion exploitation test |
| `skipDraftAccess` | `false` | Skip draft/preview access test |

**Response:** `url`, `totalFindings`, `findings[]` (category, severity, title, description, details), `schema` (totalTypes, queryTypes, mutationTypes, subscriptionTypes, hasMutations, hasSubscriptions, sensitiveTypes, rateLimit), `errors[]`, `elapsedMs`.

**MCP:** `browser_security_graphql_analyze`.

### POST /api/security/verify
Exploit verifier — proves a vulnerability by **inject** (optional browser `fetch`), **navigate** to render page, **evaluate** a JavaScript effect expression, optionally **screenshot** and **cleanup**. Use to confirm scanner/fuzzer findings (reduces false positives).

**DOM XSS:** use **`renderInjection`** to place payload in query/hash/path structurally (avoids `#` fragment template issues). Set **`skipInjection: true`** (or omit `injection`) when payload is delivered only via navigation. Use **`fragmentEncode: none`** for hash-based DOM XSS.

**Safety gate:** Requires `"safetyMode": "active"`. Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `safetyMode` | Yes | `"active"` — acknowledge real payloads and navigation. (`confirmBackend: true` accepted as legacy alias) |
| `injection` | No‡ | `{ url, method?, headers?, body? \| json? }` — same shape as `POST /api/fetch`. May use `§MARKER§` / `{{MARKER}}`. Omit when using `renderInjection` + `skipInjection`. |
| `skipInjection` | No | Skip injection fetch — payload via `renderUrl` / `renderInjection` only (default `false`; auto `true` when `renderInjection` set and no `injection`) |
| `payload` | No† | Value for `§PAYLOAD§` / `renderInjection` |
| `substitutions` | No | Map of marker name → string |
| `renderUrl` | Yes | Base URL to navigate after injection (where effect should appear) |
| `renderInjection` | No | Structured placement: `{ part: query\|hash\|path, param?, encode?, append? }` — **`encode: none`** for hash DOM XSS |
| `queryEncode` | No | Encoding for query markers / `renderInjection` query (default `component`) |
| `fragmentEncode` | No | Encoding for hash/fragment markers (default **`none`**) |
| `effectCheck` | Yes | JavaScript **expression** on render page (e.g. `window.__xss_proof === 1`) |
| `cleanup` | No | Optional post-verify `fetch` |
| `encodePayloadInUrl` | No | URI-encode query-side `§MARKER§` in template URLs (default `true`; fragment uses `fragmentEncode`) |
| `waitAfterRenderMs` | No | Delay after navigation before effect check (default `0`) |
| `waitForIdleAfterRender` | No | Wait for network idle after render (default `false`) |
| `fetchTimeoutMs` | No | Per-`fetch` timeout (default `30000`) |
| `includeScreenshot` | No | Base64 screenshot in `evidence` (default `true`) |
| `screenshotFormat` | No | `jpeg` (default) or `png` |
| `screenshotQuality` | No | JPEG quality 1–100 (default `70`) |

† Required when templates contain markers or when `renderInjection` is set.  
‡Not required for DOM XSS verify with `renderInjection` + `skipInjection`.

**Example — hash DOM XSS:**
```json
{
  "safetyMode": "active",
  "renderUrl": "https://app/vuln.html",
  "renderInjection": { "part": "hash", "encode": "none" },
  "payload": "<img src=x onerror=alert(1)>",
  "effectCheck": "window.__xss_proof === 1",
  "skipInjection": true
}
```

**Response `data`:** `verified`, `effectObserved`, `effectValue`, `evidence` (`payloadDelivered`, `renderPageLoaded`, `effectCheckResult`, `screenshot`, `injectionStatus`), `cleanedUp`, `error`, `elapsedMs`.

**Response `data`:** `verified`, `effectObserved`, `effectValue`, `evidence`, `cleanedUp`, `error`, `elapsedMs`. Implemented as a thin wrapper over **verify-workflow** (trigger inject + oracle effectCheck).

**MCP:** `browser_security_verify` (legacy shape; compiles to verify-workflow internally).

### POST /api/security/verify-workflow
**Primary proof API** — `setup` → `trigger` → `oracle` → `cleanup`. Oracle verdict is deterministic (machine decides pass/fail).

**Step types:** `identity`, `navigate`, `fetch`, `wait`, `waitForIdle`, `screenshot`, `capture`, `inject` (ExploitVerifier), plus legacy REST `path`/`method` steps.

**Oracle types:** `effectCheck`, `expression`, `fetch`, `peerFetch`, `domDiff`, `networkMatch`, `cookieDelta`, `storageDelta`, `screenshotCompare`, `and`, `or`.

**Capture → oracle vars:** fetch steps may include `capture` to bind response fields into `{{varName}}` for oracle `expression` checks. Both conventions work: `{ "adminBody": "body" }` (var → field) and `{ "status": "sqliStatus" }` (field → var).

| Field | Required | Description |
|-------|----------|-------------|
| `safetyMode` | Yes | `"active"` — real payloads / navigation. (`confirmBackend: true` accepted as legacy alias) |
| `oracle` | Yes | Oracle spec object |
| `setup` / `trigger` / `cleanup` | No | Step arrays |
| `exportEvidence` | No | Write bundle under `%LocalAppData%\Trowser\Evidence\{workflowId}\` |

**MCP:** `browser_security_verify_workflow`.

### POST /api/security/chain-prove
Run a **proof template** for a `patternId`. Resolves `proofTemplateId` when it differs from pattern id. Substitutes `{{endpoint}}`, `{{param}}`, and other placeholders from matched chain findings. Checks required identity snapshots before cross-identity templates.

| Field | Required | Description |
|-------|----------|-------------|
| `safetyMode` | Yes | `"active"` — executes proof workflow. (`confirmBackend: true` accepted as legacy alias) |
| `patternId` | Yes | Chain pattern ID |
| `endpoint` / `sensitiveEndpoint` | No | Override sensitive data URL (`endpoint0` in templates) |
| `corsEndpoint` | No | Override CORS misconfigured URL (`endpoint1` in templates) |
| `vars` | No | Object of template variable overrides merged after auto-substitution (e.g. `balanceUrl`, `step1Url`, `step1Body` for `fail-open-transaction`). Aliases: `substitutions`, `templateVars`. Same keys may also be passed top-level. |
| `exportEvidence` | No | Export bundle on success/failure |
| `exportTrwPath` | No | Copy `scenario.trw` from bundle to repo path after prove |

**Template vars:** when a proof template needs placeholders not derivable from findings (e.g. `transaction-rollback-proof`), pass them in `vars`. Example: `{ "vars": { "balanceUrl": "https://host/api/Balance", "step1Url": "…", "step1Body": "{…}", "step2Url": "…", "step2Body": "{…}" } }`. Non-string JSON values are serialized into the template as raw JSON. **`transaction-rollback-proof`** requires readable balance GETs (HTTP 2xx, JSON body) before and after the mocked failure — identical 401 HTML error pages do not prove rollback.

**Journal:** proofs write observation entries (`chain-prove`, `evidence-export` tags).

**Failure diagnostics:** when `proven: false`, response includes `failurePhase`, `failureDetail`, `templateExpanded`, `attemptedSubstitutions`, and `stepErrors[]`.

**MCP:** `browser_security_chain_prove`. Full chains show `provable`, `missingIdentities[]`, and `suggestedAction` (chain-prove → evidence/rerun).

### POST /api/security/evidence/export · POST /api/security/evidence/rerun
Export proof bundles (workflow JSON, `scenario.trw`, oracle verdict, chain metadata when from chain-prove) and re-run for fix verification.

Bundles include: `bundle.json`, `workflow.json`, `scenario.trw`, `manifest.json` (with `patternId` when applicable).

**Export modes:**
- **`bundlePath` only** — re-export or redact an existing bundle (read-only; **no** `safetyMode` required).
- **Workflow body** — run `verify-workflow` and write a new bundle (**requires** `safetyMode: "active"`).

| Field | Required | Description |
|-------|----------|-------------|
| `bundlePath` | For re-export | Path from a prior export manifest |
| `redact` | No | When re-exporting, copy to `-redacted` folder (default `true`) |
| `safetyMode` | When running workflow | `"active"` to execute trigger/inject steps. (`confirmBackend: true` accepted as legacy alias) |
| `workflow` / inline phases | When running workflow | Same shape as `verify-workflow` |

**Rerun** returns `VERIFIED | NOT_VERIFIED | INCONCLUSIVE` (optional `expect: NOT_VERIFIED` after patch).

**MCP:** `browser_security_evidence_export`, `browser_security_evidence_rerun`.

### GET /api/vpx/export
Export session findings as a **VPX 1.0** document (Vulnerability Proof eXchange). Spec: `VPX/spec/VPX-1.0.md`.

| Query | Default | Description |
|-------|---------|-------------|
| `profile` | `compact` | `compact` or `full` |

**Response:** VPX JSON (`Content-Type: application/vnd.vpx+json`). Includes `surfaces`, `findings` (shadow + auto-scan + manual chain-findings), `proofs` (from `verify-workflow` / `chain-prove` in session), and derived `verdicts`.

Link proofs to findings with `vpxFindingId` on workflow bodies. **Gate-free** — allowed in safe mode.

**MCP:** `browser_vpx_export` — optional `profile`.

### POST /api/vpx/import
Import a VPX 1.0 document into the session — registers findings for proof queue (`source: vpx-import`), surfaces, proofs, and verdicts.

| Field | Default | Description |
|-------|---------|-------------|
| `document` | — | VPX object (or pass document fields inline) |
| `mode` | `merge` | `merge` or `replace` (replace clears prior import) |
| `action` | — | `clear` — remove imported VPX state |

**Response:** `findingsImported`, `findingsSkipped`, `proofsImported`, `verdictsImported`, `surfacesImported`, `documentId`, `warnings[]`.

**Gate-free** — allowed in safe mode. After import, run proofs with `vpxFindingId` on workflows, then `GET /api/vpx/export` for merged document.

**MCP:** `browser_vpx_import`.

### POST /api/security/verify/batch
Same verification flow as `/api/security/verify`, **sequentially**, in one **shared browser session** (cookies/login preserved between items).

**Body:** `safetyMode` (once), `items` — array of objects with the **same fields as single verify** (omit per-item `safetyMode`).

**Response `data`:** `count`, `results[]` — each entry has `index`, `ok` (parse success), plus `verified`, `effectObserved`, `evidence`, etc., or `parseError` on failure.

### POST /api/security/callbacks · GET /api/security/callbacks
Out-of-Band interaction detection. Monitors browser network log for requests whose **host** is the callback domain (default: `callback.trowser.test`) — not merely when the domain string appears in a query parameter on another site. Detects blind XSS, DOM SSRF, CSS injection exfiltration — client-side OOB that proxy tools cannot see.

**POST — Start/Stop/Clear:**

| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `"start"` | `start`, `stop`, `status`, `clear` |
| `domain` | `"callback.trowser.test"` | Custom callback domain |

Use `{{CALLBACK}}` in fuzz payloads — auto-substituted with callback URL (ASCII-safe). Legacy `§CALLBACK§` is still accepted.

**GET** — Poll interactions. Returns `interactions[]` with `timestamp`, `url`, `method`, `correlationId`, `finding`. **Gate-free**.

**MCP:** `browser_security_callbacks`.

---

### Attack Chain Engine

Analyzes security findings from **shadow**, **auto-scan**, **parser-probe/cmd-canary**, **session journal** (bugs/enhancements with security tags or `category` field), and manual chain-findings to discover **multi-step attack chains**. Ships with 20+ built-in patterns.

### POST /api/security/chain-analyze

Run chain discovery on all available findings. **Read-only — allowed in safe mode; gate-free**.

**Finding sources:** shadow (when enabled), auto-scan, parser-probe, cmd-canary, journal entries (`bug`/`enhancement`/`observation` with tags matching `knownCategories`, `category:` tag prefix, or `fields.category`), manual `chain-findings`.

| Field | Default | Description |
|-------|---------|-------------|
| `minChainedSeverity` | — | Minimum chained severity: `critical`, `high`, `medium`, `low` |
| `includePartial` | `true` | Include partial chains with at most one missing required link |

**Response `data`:** `chains[]` includes `provable`, `missingIdentities[]`, `suggestedAction` — only patterns with **at least one matched finding** (all-optional patterns with zero evidence, e.g. phantom OAuth PKCE chains, are excluded). `partialChains[]` includes `missingCategories[]`, `missingIdentities[]`, `suggestedAction` (probe, identity capture, or chain-prove when ready).

### GET /api/security/chain-findings

Returns all available findings normalized into chainable format. **Gate-free**.

| Query param | Description |
|-------------|-------------|
| `category` | Filter by category substring (e.g. `xss`, `csrf`, `idor`) |

**Response `data`:** `count`, `knownCategories[]` (all accepted finding categories), `findings[]` (each with `id`, `category`, `severity`, `title`, `endpoint`, `method`, `evidence`).

Manual add via `POST /api/security/chain-findings` requires `category` from `knownCategories`.

### GET /api/security/chain-patterns · POST /api/security/chain-patterns

**GET** — List all chain patterns (built-in + custom). **Gate-free**.

**POST** — Add or remove custom patterns. **add/remove blocked in safe mode**.

| Field | Description |
|-------|-------------|
| `action` | `"add"`, `"remove"`, or `"list"` (default) |
| `id` | Pattern ID (required for add/remove) |
| `name` | Pattern name (required for add) |
| `description` | Narrative template with `{0}`, `{1}` placeholders |
| `severity` | Chained severity: `critical`, `high`, `medium` |
| `impact` | Impact category (e.g. `account-takeover`, `rce`) |
| `proofTemplateId` | Proof template key (enables `chain-prove` for custom patterns) |
| `links` | **Preferred:** `[{ requiredCategory, role?, optional?, constraint?, endpointPattern? }]` min 2 |
| `categories` | **Legacy:** category names only (min 2) — maps to default enabler links |

**GET response** includes `proofTemplateId`, `provable`, full `links[]`.

**MCP:** `browser_security_chain_analyze`, `browser_security_chain_patterns`.

---

### WebSocket Security Testing

Passive WebSocket traffic capture via CDP (connections, frames, handshake details) plus active security auditing (origin validation, auth checks, sensitive data scanning, CSWSH testing).

### GET /api/websocket/connections

List all WebSocket connections tracked for the active tab. **Gate-free**.

| Query param | Description |
|-------------|-------------|
| `url` | Filter connections by URL substring |

**Response `data`:** `count`, `connections[]` (each with `connectionId`, `cdpRequestId`, `url`, `state`, `protocol`, `framesSent`, `framesReceived`, `bytesSent`, `bytesReceived`, `createdAt`, `closedAt`, `hasHandshake`).

### GET /api/websocket/messages

Query WebSocket frames across connections. **Gate-free**.

| Query param | Default | Description |
|-------------|---------|-------------|
| `connectionId` | — | Filter to a specific connection |
| `direction` | — | `"sent"` or `"received"` |
| `search` | — | Text search in frame payload |
| `limit` | `100` | Max frames to return |

**Response `data`:** `count`, `frames[]` (each with `connectionId`, `direction`, `dataType`, `data`, `dataLength`, `isJson`, `jsonType`, `timestamp`).

### POST /api/websocket/send · POST /api/websocket/close

Send a message or close an active WebSocket connection via an injected page hook (`window.__trowserWs*`). Requires an active connection from the current page (see `GET /api/websocket/connections`). **Blocked in safe mode.**

**Send** — `POST /api/websocket/send`

| Field | Description |
|-------|-------------|
| `connectionId` | **Required.** Connection ID from `GET /api/websocket/connections` |
| `message` | **Required.** Payload to send |

**Close** — `POST /api/websocket/close`

| Field | Description |
|-------|-------------|
| `connectionId` | **Required.** |
| `code` | Optional close code (default 1000) |
| `reason` | Optional close reason |

**MCP:** `browser_websocket_send`, `browser_websocket_close`.

### POST /api/security/websocket-audit

Run security audit on WebSocket connections. Checks: **origin** validation, **authentication** mechanism (cookies, tokens in URL, no auth), **TLS** (ws:// vs wss://), **sensitive data** in frames (emails, JWTs, API keys, passwords, credit cards, SSNs, internal IPs), **input validation** (HTML/script content in received frames), **message type surface** analysis. Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `connectionId` | — | Audit a specific connection (default: all) |

Findings are auto-pushed to **Shadow Mode** when enabled.

**Response `data`:** `connectionsAudited`, `totalFindings`, `bySeverity` (object), `results[]` (each with `connectionId`, `url`, `findings[]`, `messageTypeDiscovery`, `elapsedMs`).

**MCP:** `browser_security_websocket_audit`.

### POST /api/security/websocket-fuzz

Active WebSocket message fuzzing. Sends payload catalogs (`xss-basic`, `sqli-basic`, `json-breaking` by default) via `websocket/send`, inspects received frames for reflection/HTML/SQLi indicators, and replays privileged JSON **message types** from captured traffic.

**Safety gate:** Requires `"safetyMode": "active"`. Requires active WebSocket connections. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `connectionId` | all open | Target a specific connection |
| `payloadSets` | xss/sqli/json-breaking | Fuzzer payload set names |
| `maxPayloadsPerSet` | `8` | Cap per set |
| `includeMessageTypeMatrix` | `true` | Replay privileged message types |
| `responseWaitMs` | `500` | Wait after send before checking frames |

**MCP:** `browser_security_websocket_fuzz`.

### POST /api/security/cswsh-test

**Cross-Site WebSocket Hijacking** test. Crafts a raw WebSocket Upgrade request from an attacker-controlled Origin with the victim's session cookies. Tests whether the server validates the Origin header. Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `url` | auto-detect | Target WebSocket URL (ws:// or wss://). Auto-detects from active connections if omitted. |
| `origin` | `"https://evil.example.com"` | Attacker origin to test with |
| `cookies` | — | JSON object of cookies to include in handshake |
| `protocol` | — | Sec-WebSocket-Protocol to request |
| `sendAfterConnect` | — | Message to send after connection (e.g. GraphQL `connection_init`) |
| `preset` | — | `"graphql-ws"` auto-fills `sendAfterConnect` with `connection_init` |
| `graphqlPayload` | — | Optional JSON for GraphQL WS `connection_init` payload |
| `monitorMs` | `5000` | How long to listen for incoming messages after connecting |
| `timeoutMs` | `10000` | Connection timeout |

**Response `data`:** `targetUrl`, `testedOrigin`, `vulnerable` (bool), `severity`, `detail`, `handshakeStatus`, `receivedMessages[]`, `evidence`, `elapsedMs`.

Vulnerable findings are auto-pushed to **Shadow Mode**.

**MCP:** `browser_security_cswsh_test`.

### POST /api/validate-html
HTML markup validation (html-validate). No params needed.

### POST /api/compatibility
JavaScript backward compatibility analysis (iOS 15, Android 10). No params needed.

### POST /api/check-links
Check all links on the page for broken URLs, redirects, and errors. Sends HEAD requests (falls back to GET on 405). Redirects are observations, not errors.

| Field | Default | Description |
|-------|---------|-------------|
| `scope` | `"anchors"` | `anchors` (`<a>` tags only), `resources` (images, scripts, stylesheets, iframes), `all` |
| `external` | `true` | Whether to check links to external domains |
| `timeoutMs` | `5000` | Timeout per request in milliseconds |
| `concurrency` | `10` | Number of parallel requests |
| `delayMs` | `100` | Milliseconds between requests to avoid rate limiting. `0` = no delay |

### POST /api/security/xss
DOM XSS audit (passive). Scans page DOM for XSS-prone patterns: inline event handlers, `javascript:` URLs, dangerous sinks (`eval`, `document.write`, `innerHTML`), cross-domain scripts without SRI, `data:` URIs in iframes, external form actions, base tag hijacking. Also reports **`dom-xss-flow`** findings when URL/DOM sources (`location.hash`, `location.search`, `document.referrer`, etc.) appear near dangerous sinks in inline scripts — with `source`, `sink`, and `confidence` fields. No params needed. Inspired by OWASP ZAP passive scan rules.

**MCP:** `browser_security_xss`.

### POST /api/security/xss-scan
Active XSS scan with **unified findings**. Reflected path: character-survival fingerprint → context-driven payloads → optional **DOM verify** (sink/CSP oracles) on `standard`/`deep`. DOM path: navigate + auto-bypass. No noisy default `javascript:` iframe payload.

**Safety gate:** `"safetyMode": "active"`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` |
| `url` + `paramName` | — | Explicit base URL + parameter (reflected + DOM candidates) |
| `request` | — | Optional `{ url, method?, headers?, body? \| json? }` with `§marker§` / `{{marker}}` |
| `depth` | `standard` | `quick` \| `standard` \| `deep` (deep enables stored by default) |
| `includeReflected` | `true` | Fetch-based reflection analysis |
| `includeDom` | `true` | Navigate + sink monitor |
| `includeStored` | from depth | Stored XSS POST+readback |
| `maxCandidates` | from depth | Cap on discovered candidates |
| `maxBypassAttempts` | from depth | Auto-bypass variants per DOM candidate |
| `timeoutMs` | `10000` | Per-probe timeout |
| `minConfidence` | `likely` | Filter findings |
| `includeHygiene` | `false` | Include non-exploitable tiers |

**Response:** unified envelope. Categories: `xss-reflected`, `xss-dom`, `xss-stored`.

**MCP:** `browser_security_xss_scan`.

### POST /api/page-text/structured
Extract all page text in a structured format for proofreading. Returns `headings` (with hierarchy), `paragraphs`, `links` (text + URL), `buttons`, `labels`, `images` (alt + src), `metaDescription`, `language`, `wordCount`, `allText`. No params needed.

### POST /api/consistency
GUI consistency & image optimization audit. Analyzes computed styles to count distinct font families, font sizes, text/background colors, button/input heights, and spacing values. Also checks images for optimization issues (oversized images, missing dimensions, missing lazy loading). Warns when counts exceed thresholds (e.g., >4 font families, >10 text colors). No params needed.

### POST /api/third-party
Third-party resource inventory. Scans for external scripts, stylesheets, iframes, and fonts. Reports domains, transfer sizes (from Performance API), and Subresource Integrity (SRI) coverage. Useful for privacy audits, GDPR compliance, and supply chain security. No params needed.

### POST /api/security/mixed-content
Mixed content detection. On HTTPS pages, finds all resources loaded over HTTP. Reports element tag, attribute, URL, and severity (High = scripts/iframes, Medium = images/stylesheets, Low = other). Returns clean result on HTTP pages. No params needed.

### POST /api/security/source-maps
Source map & debug mode audit. Detects `sourceMappingURL` directives in HTML/JS/CSS, probes for accessible `.map` files (information disclosure — original source code), and checks for debug globals (Angular `ng.probe`, React DevTools hook, Vue DevTools hook, Redux DevTools). Severity: HIGH = accessible `.map` files, MEDIUM = sourceMappingURL references, LOW = debug mode indicators. No params needed.

### POST /api/security/tech-stack
Technology stack fingerprinting. Detects web servers (Nginx, Apache, IIS, Kestrel, etc.), frameworks (ASP.NET, Express, Django, Rails, Laravel, Spring), languages (PHP, Java, Python, Ruby), JavaScript libraries/frameworks (React, Angular, Vue, jQuery, Next.js, Bootstrap), WAFs (Cloudflare, Akamai, Imperva/Incapsula, Sucuri), CDNs (CloudFront, Vercel, Netlify, Fastly), CMSes (WordPress, Drupal, Shopify), and analytics (Google Analytics, Hotjar, Segment). Combines HTTP response headers, cookies, DOM patterns (meta tags, data attributes, global JS objects), and script URL analysis. Each detection includes `name`, `version` (if available), `category`, `evidence`, `source`, and `confidence` (0–1). No params needed. Included in `POST /api/audit-all`.

**Response:** `detectionCount`, `categories`, `detections[]`, `frameworks[]`, `servers[]`, `jsLibraries[]`, `waf[]`, `cdn[]`, `elapsedMs`, `summary`.

**MCP:** `browser_security_tech_stack`.

### POST /api/security/cookies
Cookie security audit (OWASP best practices). **Reconciles** cookie-jar data with **Set-Cookie headers from the network log** (authoritative for HttpOnly/Secure/SameSite — fixes false positives when HttpOnly cookies are invisible to `document.cookie`). Checks all cookies for: missing Secure flag on HTTPS, **HttpOnly** on session/auth cookies (name-pattern heuristics **plus** non-expiring session cookies that are not known analytics/consent names — e.g. app-named tokens), SameSite=None issues, overly broad domain scoping, and excessive cookie lifetimes. **Known vendor analytics cookies** (Dynatrace `dtPC`/`dtSa`/`dtCookie`/`rxvt`/`rxVisitor`, Hotjar `_hjSession*`/`_hjId`, Google Analytics `_ga*`/`__utm*`, Facebook Pixel `_fbp`/`_fbc`) are **excluded from HttpOnly checks** — these are JS-readable by design. Returns `findings`, `checklist`, `primarySource`, and `networkReconciledCookies`. Falls back to CDP `Network.getCookies` when WebView2 CookieManager is unavailable. Included in `POST /api/audit-all`. No params needed.

### POST /api/security/session-id
Session identifier strength analysis. Detects low entropy, sequential IDs, timestamp-embedded values, and MD5-of-counter patterns. Uses current session cookies plus historical values from **Set-Cookie** entries in the network log. **Optional:** `cookieName`, `samples` (extra values), `pageNetworkOnly` (default `false`). Browse/login multiple times to populate the network log before running for best coverage.

### POST /api/security/storage
Web storage security audit. Scans localStorage and sessionStorage for: auth tokens/JWTs stored client-side (HIGH for localStorage), PII (emails, SSNs, phone numbers), HTML/script content that could be a stored XSS vector, and credentials/secrets. Returns `findings` with severity, category, key name, and remediation advice. Included in `POST /api/audit-all`. No params needed.

### POST /api/security/saml-decode
Decode SAML messages from the network log or raw input. Handles both HTTP-Redirect binding (URL-encoding → Base64 → DEFLATE) and HTTP-POST binding (Base64). Parses XML into structured fields and performs security analysis (missing signatures, weak algorithms, expired assertions, missing audience restrictions, conflicting AuthnRequest flags, suspicious ProtocolBinding/ACS URLs). Gracefully handles invalid content (fuzzing payloads) — skips to next match or reports error. References CVE-2025-47949 (samlify), CVE-2025-25291/25292 (ruby-saml).

| Field | Default | Description |
|-------|---------|-------------|
| `source` | `"network"` | `"network"` to auto-find in network log, `"raw"` to decode a provided value |
| `networkFilter` | *(none)* | URL substring filter when source="network" (e.g. "SAMLRequest", "sso") |
| `raw` | *(none)* | Raw SAML parameter value when source="raw" |
| `encoding` | `"redirect"` | `"redirect"` (URL+Base64+DEFLATE) or `"post"` (Base64) |
| `findAll` | `false` | Return ALL SAML messages from network log as an array (valid + invalid) |

**Response (single):** `{ binding, messageType, parameterName, xml, parsed: { ... }, signature: { present, algorithm, location }, securityFindings: [{ severity, category, description }] }`

**Response (findAll):** `{ count, successCount, errorCount, messages: [{ success, networkEntryId, data: { ... } }] }`

**MCP:** `browser_saml_decode`

### POST /api/security/saml-capture
Capture SAML assertions during SSO login flows. Four modes: `next-login` arms auto-capture for the next SAMLResponse POST, `network` searches existing log, `disarm` cancels, `status` checks. Set `captureRequests: true` to also capture the outgoing SAMLRequest for comparison.

| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `"next-login"` | `"next-login"`, `"network"`, `"disarm"`, or `"status"` (MCP only) |
| `url` | *(none)* | URL filter when mode="network" |
| `captureRequests` | `false` | Also capture outgoing SAMLRequest when mode="next-login" |

**GET /api/security/saml-capture** — Poll capture status. Returns `{ status: "armed"|"idle"|"captured", ... }`. When captured, includes full decoded assertion (and `samlRequest` if `captureRequests` was enabled).

**MCP:** `browser_saml_capture` (also supports `mode: "status"` to poll)

### POST /api/security/saml-replay
Replay a captured SAML assertion with modifications for security testing. Requires a previously captured assertion or a raw assertion XML/Base64. Tests: signature removal, identity spoofing, expired assertion acceptance, audience restriction bypass, issuer spoofing. Returns structured response with HTTP status code.

**Safety gate:** Requires `"safetyMode": "active"` context — sends modified assertions to the SP.

| Field | Default | Description |
|-------|---------|-------------|
| `targetUrl` | *(captured URL)* | SP assertion consumer service URL |
| `assertion` | *(captured)* | Raw assertion XML or Base64 (optional — uses captured if omitted) |
| `removeSignature` | `false` | Remove XML signatures (CVE-2025-47949, CVE-2025-25291/25292) |
| `changeSubject` | *(none)* | Change NameID to test identity spoofing |
| `expireAssertion` | `false` | Set NotOnOrAfter to past time |
| `extendValidityMinutes` | *(none)* | Extend validity window by N minutes |
| `removeAudienceRestriction` | `false` | Remove AudienceRestriction for cross-SP replay |
| `changeIssuer` | *(none)* | Change Issuer value |
| `customXml` | *(none)* | Full custom XML assertion (bypasses all built-in modifications) |
| `dryRun` | `false` | Preview modifications without sending |

**Response:** `{ targetUrl, modifications, responseStatus, responseStatusText, responseUrl, redirected, bodyLength, response, timestamp }`

**MCP:** `browser_saml_replay`

---

## Security Orchestration (Playbooks)

Goal-oriented orchestration layer: one call per OWASP category, one prioritized report. Each playbook composes Trowser's existing primitives (auto-scan, CORS sweep, secrets harvest, supply-chain scan, etc.) into a sequenced pipeline with unified safety, depth, and budget controls.

> **Browse manually, then scan with `crawl: false`.** Playbooks default to **`crawl: false`** — they scan traffic already in the network log. Browse login, search, and CRUD flows first; set **`crawl: true`** only when you want the playbook to auto-discover links/forms before scanning. For probe-heavy playbooks (`a05-injection`, `a01-access`, …), set **`scope.targetUrl`** to one captured endpoint for a fast focused run, or **`depth: "deep"`** for explicit broader coverage (default standard depth probes at most **2** endpoints site-wide).

All orchestration endpoints share the **same request envelope** and return the **same response envelope**. VPX is always produced internally; the `format` parameter controls the rendering.

### Common Request Body

```json
{
  "scope": {
    "host": "example.com",
    "includePaths": ["/api/*"],
    "excludePaths": ["/admin/*", "/settings/delete*"],
    "excludeUrlPatterns": ["(?i)/dangerous"],
    "excludeLogout": true,
    "identities": ["anon", "alice", "admin"],
    "targetUrl": "https://example.com/api/search?q=test"
  },
  "safetyMode": "safe",
  "depth": "standard",
  "crawl": false,
  "budget": { "maxSeconds": 120, "maxRequests": 800 },
  "evidence": "auto",
  "emitSuggestedProofs": true,
  "tags": ["pre-prod", "sprint-42"],
  "format": "vpx-compact",
  "embedVpx": false,
  "persistVpx": true
}
```

All fields are optional with sensible defaults.

| Field | Default | Description |
|-------|---------|-------------|
| `scope.host` | current page | Target host |
| `scope.includePaths` | `[]` | Glob patterns to include (empty = all paths). Applied to crawl and probe target selection |
| `scope.excludePaths` | `[]` | Glob patterns to exclude from crawl and probe target selection |
| `scope.excludeUrlPatterns` | `[]` | Regex patterns matched against path+query (in addition to globs) |
| `scope.excludeLogout` | `true` | Skip logout/sign-out/SLO URLs during crawl and when selecting probe targets. Does **not** block `logout-invalidation-probe` / intentional a07 logout testing |
| `scope.identities` | `[]` | Identity names from IdentityStore for multi-role testing |
| `safetyMode` | `"safe"` | `passive` (zero probes) · `safe` (GET/HEAD/OPTIONS only) · `active` (all verbs) · `aggressive` (stress/brute-force) |
| `depth` | `"standard"` | `quick` (1 probe endpoint, passive scans up to 5) · `standard` (2 probe endpoints, passive up to 20) · `deep` (broader probe coverage — up to 100 endpoints, explicit opt-in) |
| `crawl` | `false` | Alias for `includeCrawl`. When `false` (default), skips the shared `crawl-light` step — **use after manual browsing** |
| `includeCrawl` | `false` | When `false` (default), skips the shared `crawl-light` step. Prefer `crawl` for brevity |
| `scope.targetUrl` | — | **Recommended for probe playbooks.** Restrict scanners to one captured endpoint URL (must exist in network log). Caps probe steps to that endpoint |
| `scope.targetMethod` | — | Optional method with `scope.targetUrl` (e.g. `POST`). Alias: `scope.target.url` / `scope.target.method` |
| `budget.maxSeconds` | `120` | Wall-clock budget (auto-raised to playbook minimum if too low) |
| `budget.maxRequests` | `800` | Request-count budget (auto-raised to playbook minimum if too low) |
| `evidence` | `"auto"` | `none` · `auto` · `full` |
| `format` | `"vpx-compact"` | `vpx` · `vpx-compact` · `vpx-summary` · `markdown` · `sarif` |
| `embedVpx` | `false` | When `format=markdown`, also include the VPX document as `vpxAttached` |
| `persistVpx` | `true` | Store VPX in session for later `/api/vpx/export` merging |

The shared **`crawl-light`** step (when `crawl: true`) only follows links and form actions on **`scope.host`** — external sites linked from the page (e.g. partner portals) are not visited. Path filters (`includePaths` / `excludePaths` / `excludeUrlPatterns` / `excludeLogout`) are applied during crawl and when narrowing attack-surface endpoints for probes. **Default workflow: browse key flows manually, then run with `crawl: false`.** Set **`crawl: true`** when you have not browsed and want auto-discovery first. The **`full`** playbook runs crawl once at the start when enabled; nested category playbooks do not re-crawl.

Probe-heavy steps (injection, IDOR, SSRF, race conditions, etc.) rank captured endpoints and scan at most **1** (`quick`), **2** (`standard`), or **`MaxEndpointsPerScanner`** (`deep`) unless **`scope.targetUrl`** pins a single endpoint.

#### `safetyMode` semantics

| Mode | HTTP verbs | Side effects | Disables |
|------|-----------|--------------|----------|
| `passive` | None — observes page only | Zero outbound probes | All active scans |
| `safe` | GET / HEAD / OPTIONS | No state-changing requests | Mass-assignment, brute-force, race-condition, load-test |
| `active` | All verbs | May create/modify test data | High-volume DoS, load-test > 25 req |
| `aggressive` | All verbs + stress | May exhaust quotas, trigger WAF bans | Nothing — "I own this lab" mode |

`aggressive` is **refused** (HTTP 200 with error) for non-localhost/non-`*.test`/non-`*.local` hosts unless `--dangerous-ok` is set. When `--dangerous-ok` is active, the response includes a warning: `"Aggressive mode allowed for '<host>' because --dangerous-ok is set."` `active` is capped to `safe` when `--safe-probes-only` is set.

### Common Response Envelope

```json
{
  "playbookId": "a01-access",
  "runId": "9c4a..e2",
  "scope": { ... },
  "safetyMode": "safe",
  "depth": "standard",
  "startedAt": "...",
  "finishedAt": "...",
  "stepsExecuted": [
    { "name": "attack-surface", "status": "ok", "durationMs": 412, "metrics": { "endpointsDiscovered": 84 } },
    { "name": "idor-scan", "status": "ok", "durationMs": 8133, "metrics": { "findings": 3 } },
    { "name": "bfla-probe", "status": "skipped", "reason": "no admin role configured" }
  ],
  "budgetUsed": { "requests": 412, "seconds": 73 },
  "warnings": [],
  "assertionsAdded": 14,
  "nextActions": [
    { "action": "verify-workflow", "workflowId": "wf-idor-order-42", "rationale": "Confirms the IDOR with a reproducible 2-step proof." },
    { "action": "run-playbook", "playbookId": "a07-authn", "rationale": "Cross-tenant IDOR + weak session invalidation could chain." }
  ],
  "vpx": { ... }
}
```

The `vpx`, `markdown`, or `sarif` key is present depending on the requested `format`. Step `status` is one of: `ok`, `skipped`, `error`, `budget-exhausted`, `cancelled`.

### GET /api/orchestrate/playbooks

Returns the catalog of all available playbooks.

**Response:** `[{ "id": "a01-access", "title": "A01 Access Control", "category": "access-control", "endpoint": "/api/orchestrate/a01-access" }, ...]`

### POST /api/orchestrate/dry-run/{id}

Returns the step plan for a playbook **without executing any probes**. Use to preview what would happen at a given `safetyMode` and `depth`. Analyzes the **current network log** to size budgets dynamically — a dry-run after browsing returns higher recommendations than on a blank page.

**Body:** Same as orchestrate (`safetyMode`, `depth`, `scope`, `budget`).

**Budget object:** `{ "maxSeconds": 120, "maxRequests": 800, "adaptive": false }`. Set `"adaptive": true` to allow mid-run budget extensions (up to 3× +25%) when auto-scan steps are progressing.

**Response:**

```json
{
  "playbookId": "a01-access",
  "safetyMode": "safe",
  "depth": "standard",
  "steps": [
    {
      "name": "attack-surface",
      "description": "Analyze network log to discover API endpoints",
      "httpVerbs": "none (passive)",
      "writesSideEffects": false,
      "skippedByCurrentSafetyMode": false,
      "estimatedSeconds": 3,
      "estimatedRequests": 0,
      "skippedByBudget": false
    },
    {
      "name": "csrf-scan",
      "description": "Scan state-changing endpoints for CSRF vulnerabilities",
      "httpVerbs": "GET, POST",
      "writesSideEffects": true,
      "skippedByCurrentSafetyMode": true,
      "skipReason": "Requires active or aggressive mode",
      "estimatedSeconds": 0,
      "estimatedRequests": 0,
      "skippedByBudget": false
    }
  ],
  "budget": { "maxSeconds": 120, "maxRequests": 800, "adaptive": false },
  "baseRecommendedBudget": { "maxSeconds": 360, "maxRequests": 800, "adaptive": false },
  "recommendedBudget": { "maxSeconds": 600, "maxRequests": 1500, "adaptive": false },
  "estimatedCompletionSeconds": 620,
  "suggestedClientTimeoutSeconds": 775,
  "surface": {
    "networkLogEntries": 842,
    "endpointCount": 28,
    "injectableEndpointCount": 14,
    "injectableParamCount": 47,
    "averageResponseMs": 420,
    "complexityScore": 548.8,
    "networkLogEmpty": false
  },
  "budgetNotes": [
    "Large attack surface (28 endpoints): budget raised to large-site tier."
  ]
}
```

**Budget floor:** If the caller's budget is below `recommendedBudget`, the orchestrator automatically raises it to the recommended minimum and emits a warning. Per-playbook **standard-depth base** recommendations: A01 = 360s/800req, A02/A03/A04/A11 = 180s/800req, A05 = 1200s/2000req, A06/A12 = 300s/1000req, A07 = 360s/1200req, A14 = 600s/1500req, **full = 2400s/10000req**. With **20+ endpoints**, budgets scale to large-site tiers (e.g. A01 → 600s/1500req, A05 → 1800s/3000req, full → 3600s/15000req).

### POST /api/orchestrate/a01-access

**A01 Access Control.** Steps: crawl → attack-surface analysis → security headers → cookie audit → CSRF scan → IDOR / mass-assignment / BFLA (via auto-scan) → authz-diff → authz-boundary.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `attack-surface` | any | Passive network-log analysis, endpoint + auth-tier classification |
| `security-headers` | any | HTTP header audit (CSP, HSTS, X-Frame-Options, etc.) |
| `cookie-audit` | any | OWASP cookie audit (Secure, HttpOnly, SameSite) |
| `csrf-scan` | `active`+ | Test state-changing endpoints for missing CSRF tokens |
| `idor-scan` | `safe`+ | IDOR / mass-assignment / BFLA via AutoScanPipeline (read-only in `safe`, mutating in `active`+) |
| `authz-diff` | `safe`+ (requires peer) | Cross-identity response comparison — fetches endpoints as both local session and a registered peer, flags BOLA_SUSPECTED / FILTERED_RESPONSE |
| `authz-boundary` | `safe`+ | Confirms unauthorized access using harvested IDs from network log — replays requests with unauthorized values to prove IDOR |

**Peer requirement for `authz-diff`:** Register a second Trowser instance as a peer via `POST /api/peer/register` BEFORE running this playbook. The peer should be authenticated as a different user. If no peer is registered, `authz-diff` is skipped. The `authz-boundary` step runs whenever IDOR/BOLA candidates exist from either `idor-scan` or `authz-diff`.

**`nextActions` hints:** `a07-authn` (when IDOR found), `a02-misconfig` (when CSRF found), `a05-injection` (when any findings).

### POST /api/orchestrate/a02-misconfig

**A02 Security Misconfiguration.** Steps: crawl → security headers → cookie audit → source maps → CORS sweep → endpoint discovery → HTTP methods → smuggling indicators → subdomain takeover.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `security-headers` | any | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| `cookie-audit` | any | OWASP cookie security |
| `source-maps` | any | Exposed `.map` files and debug mode detection |
| `cors-sweep` | `safe`+ | CORS misconfiguration sweep across discovered API endpoints |
| `endpoint-discover` | `safe`+ | Directory/endpoint discovery (admin panels, `.env`, `.git`, config files) |
| `http-methods` | `safe`+ | Test accepted HTTP methods (TRACE XST risk, unrestricted PUT/DELETE) |
| `smuggling-passive` | any | Passive header analysis for proxy/CDN smuggling indicators |
| `subdomain-takeover` | `safe`+ | Detect dangling CNAMEs via DoH + HTTP fingerprinting (S3, GitHub Pages, Heroku, Azure, Vercel, Fastly, Netlify, etc.) |

**`nextActions` hints:** `a01-access` (when CORS misconfig), `a04-crypto` (when source maps exposed), `a14-other` (when misconfiguration findings).

### POST /api/orchestrate/a03-supplychain

**A03 Supply Chain.** Steps: crawl → source maps → supply-chain scan (Retire.js + manifest fetch + OSV lookup + CI/CD exposure + bundle fingerprinting) → SRI check → secrets harvest → deserialization + file-upload scan.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `source-maps` | any | Source map exposure and debug mode |
| `supply-chain-scan` | `safe`+ | Retire.js CVEs, manifest fetch, OSV advisory lookup, CI/CD config exposure, bundle deps |
| `firewall-sri` | any | SRI validation for third-party scripts |
| `secrets-harvest` | `safe`+ | JS bundles, cookies, storage, network for leaked secrets/credentials |
| `deserialization-scan` | `active`+ | Insecure deserialization + file upload validation bypass |

**`nextActions` hints:** `a04-crypto` (when credentials leaked), `a05-injection` (when deserialization findings).

### POST /api/orchestrate/a04-crypto

**A04 Crypto & Secrets.** Steps: crawl → HSTS/transport headers → cookie Secure/HttpOnly audit → secrets harvest → session-ID entropy → JWT analysis → source maps.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `security-headers-hsts` | any | Transport-layer headers: HSTS, CSP, X-Content-Type-Options |
| `cookie-audit-crypto` | any | Cookie Secure flag, HttpOnly flag |
| `secrets-harvest` | `safe`+ | JS bundles, cookies, storage, network, page text for hardcoded secrets/credentials. **Noise-filtered:** framework license blocks (React/Angular/MIT), standard XSRF-TOKEN config, and binary-garbage base64 are excluded; `filteredNoise` count in step metrics |
| `session-id-entropy` | any | Session token entropy, predictability, CSPRNG quality (passive, uses captured cookies) |
| `jwt-analysis` | any | JWT decode: weak algorithms (none, HS256), expired tokens, sensitive claims in payload |
| `source-maps` | any | Exposed source maps that may reveal secrets in original source |

**`nextActions` hints:** `a07-authn` (when weak JWT or weak entropy), `a01-access` (when credentials exposed).

### POST /api/orchestrate/a07-authn

**A07 Authentication.** Steps: crawl → JWT analysis → session-ID entropy → cookie audit → OIDC provider analysis → session fixation → password-reset weakness → account enumeration → logout invalidation.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `jwt-analysis` | any | JWT decode and analysis (passive, uses captured tokens) |
| `session-id-entropy` | any | Session token entropy and predictability patterns |
| `cookie-audit-authn` | any | Session cookie audit (Secure, HttpOnly, SameSite) |
| `oidc-analysis` | `safe`+ | OpenID Connect provider config: dangerous grants, weak PKCE, signing algorithms, open registration |
| `session-fixation` | `safe`+ | Session token rotation after login (detects fixation) |
| `password-reset-weak` | `active`+ | Password reset flow: guessable security questions |
| `account-enumeration` | `active`+ | Login/register response differentials for username/email enumeration |
| `logout-invalidation` | `safe`+ | Verify session is invalidated server-side after logout |

**`nextActions` hints:** `a01-access` (when auth weakness), `a04-crypto` (when weak JWT), `a11-ssrf` (when any findings).

### POST /api/orchestrate/a11-ssrf

**A11 SSRF.** Steps: crawl → SSRF orchestrator (URL-param probing + cloud metadata + JWT jku/x5u + callbacks + chain analysis) → open redirect scan → security headers.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `ssrf-orchestrator` | `safe`+ | Full SSRF: internal IPs, cloud metadata, DNS rebinding, IMDSv2 pivot (`active`+), XXE (`active`+), JWT header abuse, callback probes, chain analysis |
| `open-redirect` | `safe`+ | Open redirect scan (SSRF escalation vector) |
| `security-headers-ssrf` | any | CSP connect-src (passive) |

**`nextActions` hints:** `a01-access` (when SSRF found), `a04-crypto` (when SSRF to cloud metadata), `a07-authn` (when open redirect for OAuth chaining).

### POST /api/orchestrate/a14-other

**A14 Other.** Steps: crawl → smuggling indicators → active smuggling → host-header injection → cache deception → cache poisoning → open redirect → WebSocket fuzzing.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `smuggling-passive` | any | Proxy/CDN header analysis for smuggling indicators (Via, CF-Ray, X-Cache, X-Served-By) |
| `smuggling-active` | `active`+ | CL-TE, TE-CL, TE-TE raw TCP timing probes with TE obfuscation mutations |
| `host-header-injection` | `active`+ | Host override, X-Forwarded-Host, duplicate Host, port manipulation, absolute-URL probes |
| `cache-deception` | `safe`+ | Path confusion to cache authenticated responses publicly |
| `cache-poison` | `active`+ | Unkeyed header injection to poison cached responses |
| `open-redirect` | `safe`+ | Redirect parameter scanning with bypass payloads |
| `websocket-audit` | `safe`+ | WebSocket message injection and message-type confusion fuzzing |

**`nextActions` hints:** `a01-access` (when smuggling), `a04-crypto` (when cache issues), `a07-authn` (when host-header or open redirect).

### POST /api/orchestrate/a05-injection

**A05 Injection.** Steps: crawl → attack-surface → injection scan (SQLi, XSS, SSTI, NoSQL, LDAP, cmd-canary, parser-probe, prototype-pollution, CSTI, path-traversal) → SQLi login sweep → deserialization + file upload.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `attack-surface` | any | Passive network-log analysis, injectable endpoint classification |
| `injection-scan` | `safe`+ | SQLi, XSS, SSTI, NoSQL, LDAP, cmd-canary, parser-probe, prototype-pollution via AutoScanPipeline (read-only in `safe`, write verbs in `active`+) |
| `sqli-login-sweep` | `active`+ | SQL injection bypass on common login endpoints |
| `deserialization-scan` | `active`+ | Insecure deserialization gadgets and file upload validation bypass |

**`nextActions` hints:** `a01-access` (when SQLi found), `a07-authn` (when XSS/template injection), `a11-ssrf` (when cmd injection).

### POST /api/orchestrate/a06-design

**A06 Insecure Design.** Steps: crawl → attack-surface → workflow-step-skip → race-condition → fail-open → missing-parameter → mass-assignment (price/role/status).

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log |
| `attack-surface` | any | Passive network-log analysis — discovers POST/PUT/PATCH endpoints and feeds URLs to downstream steps |
| `workflow-step-skip` | `active`+ | Detect multi-step workflows from network log and test if intermediate steps can be bypassed (unique business logic flaw) |
| `race-condition` | `active`+ | Concurrent POST burst on single-use endpoints (coupons, transfers, votes). Uses attack-surface URLs. |
| `fail-open` | `safe`+ | Test endpoints with missing/invalid auth tokens and after error conditions |
| `missing-parameter` | `active`+ | Omit required JSON fields to test crash vs graceful validation. Uses attack-surface POST URLs. |
| `mass-assignment-design` | `active`+ | Mass-assignment with price/role/status fields targeting business logic |

**Workflow step-skip detection:** The `workflow-step-skip` step identifies multi-step workflows (e.g., checkout: cart → address → payment → confirm) by analyzing consecutive POST/PUT/PATCH requests with shared path prefixes and timing correlation. It then replays the final step without intermediates. If the server accepts it, the workflow lacks server-side state machine enforcement — a class of vulnerability no other automated tool detects.

**Tip:** Browse through a complete workflow (checkout, onboarding, multi-step form) before running this playbook to ensure the network log contains the full sequence.

**SPA note:** On SPA sites where `crawl-light` discovers few links/forms, the `attack-surface` step analyzes existing network log entries (from prior browsing or XHR/fetch calls) to discover POST endpoints. This ensures `missing-parameter` and `race-condition` work even without traditional form submissions.

**`nextActions` hints:** `a12-availability` (when race condition), `a01-access` (when fail-open), `a07-authn` (when mass-assignment).

### POST /api/orchestrate/a09-opsec

**A09 Operational Security.** Steps: crawl → attack-surface → fail-open → missing-parameter → console error harvest → network error harvest → source maps/debug mode → info-leak headers.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log and trigger errors |
| `attack-surface` | any | Passive network-log analysis — discovers POST endpoints and feeds URLs to `missing-parameter` |
| `fail-open` | `safe`+ | Probe endpoints with missing/invalid auth to detect verbose error responses |
| `missing-parameter` | `active`+ | Omit required fields to trigger server-side exceptions and stack traces. Uses attack-surface POST URLs. |
| `console-error-harvest` | any | Analyze browser console for JavaScript errors, stack traces, and debug output |
| `network-error-harvest` | any | Analyze network log for 5xx responses and leaked stack traces |
| `source-maps-debug` | any | Exposed source maps and framework debug mode indicators |
| `security-headers-info` | any | Headers that leak server info (Server, X-Powered-By, X-AspNet-Version) |

**`nextActions` hints:** `a05-injection` (when verbose errors reveal injection vectors), `a06-design` (when fail-open), `a04-crypto` (when source maps).

### POST /api/orchestrate/a12-availability

**A12 Availability.** Steps: crawl → rate-limit audit → body-size limit → ReDoS scan → GraphQL query-cost analysis (including worst-case nested query cost probes in active mode).

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log |
| `rate-limit-audit` | `safe`+ | Sequential baseline then concurrent burst to detect missing/weak rate limits |
| `body-size-limit` | `active`+ | Escalating body sizes (1KB→1MB) on POST endpoints to detect unbounded acceptance |
| `redos-scan` | `safe`+ | Single-request ReDoS timing oracle on injectable parameters |
| `graphql-cost` | `safe`+ | GraphQL depth/complexity/batching probes (auto-detects endpoint from network log) |

**`nextActions` hints:** `a07-authn` (when missing rate limits on auth endpoints), `a05-injection` (when GraphQL endpoint found).

### POST /api/orchestrate/a13-llm

**A13 AI & LLM.** Steps: crawl → LLM endpoint discovery → OWASP LLM Top 10 red-team probes → indirect prompt injection → output-to-sink tracing.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log and discover LLM/chat endpoints |
| `llm-discover` | any | Discover chat endpoints from network log and chat UI widgets from DOM |
| `llm-redteam` | `active`+ | Prompt injection, jailbreak, data exfiltration, tool abuse probes |
| `indirect-injection` | `active`+ | Indirect prompt injection via file upload or URL summarization |
| `output-sink-trace` | `active`+ | Instrument DOM sinks (innerHTML, eval, document.write) then fire canary-tagged prompts to prove injection → XSS chain |

**Output-to-sink tracing:** The `output-sink-trace` step monkey-patches dangerous DOM sinks BEFORE firing LLM probes. Each probe contains a unique canary (`TROWSER_CANARY_<guid>`). If a canary reaches innerHTML, eval, or setAttribute(onclick/href), it proves the LLM's output flows unsanitized into an executable sink — confirming prompt injection → XSS/code-exec. This bridges LLM red-team findings to traditional web vulnerability proof.

**Note:** If no AI/LLM integration is detected, red-team steps are automatically skipped with a warning.

**`nextActions` hints:** `a05-injection` (when prompt injection chains with server-side injection), `a04-crypto` (when data exfiltration), `a01-access` (when MCP tool abuse).

### POST /api/orchestrate/quick

**Quick Site Security (LLM preset).** ~60–120s bundle for agent-driven triage after manual browsing. Prefer this over `full` when you need fast, split coverage without logout side-effects.

**Execution order:**
1. `crawl-light` (optional — skipped when `"crawl": false`)
2. `attack-surface` — passive endpoint map
3. `playbook-a02-misconfig` — headers, cookies, CORS, methods
4. `playbook-a01-access` — IDOR/CSRF (safe mode)
5. `playbook-a05-injection` — injection scan (safe mode)
6. `federation-decode` — SAML decode when federation traffic exists
7. `playbook-a07-authn` — **skipped** (run separately; logout probe terminates session)

**Recommended request:**

```json
{
  "scope": { "host": "example.com" },
  "safetyMode": "safe",
  "depth": "standard",
  "crawl": false,
  "budget": { "maxSeconds": 120, "maxRequests": 800 },
  "format": "markdown"
}
```

**Budget:** Recommended minimum: **120s / 800 req** (does not scale with large attack surfaces).

**When to use:** Default LLM security sweep after browsing key flows. Follow with `a07-authn` for session/logout testing or individual playbooks for depth.

**Response contract (all orchestrate playbooks):** top-level `findings[]` (normalized finding objects) and `severityHistogram` are always populated for LLM triage. Full VPX remains under `vpx` / `data.vpx` as the export detail. `cors-sweep` is skipped at `depth: quick` (use standard/deep).

### POST /api/orchestrate/full

**Full Site Security.** Runs all playbooks in optimized order, then correlates findings across categories to discover multi-step attack chains, and autonomously attempts to complete partial chains.

**Execution order:**
1. **Passive tier:** A02 (misconfig) → A04 (crypto) → A03 (supply chain)
2. **Core tier:** A01 (access) → A07 (authn) → A11 (ssrf) → A14 (other)
3. **Extended tier:** A05 (injection) → A06 (design) → A09 (opsec) → A12 (availability) → A13 (llm)
4. **Chain correlation:** Cross-category attack chain discovery using all accumulated findings
5. **Chain completion:** Auto-loop that runs suggested scanners to fill partial chains (up to 3 iterations)

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | Shared BFS crawl to populate network log |
| `playbook-a02-misconfig` | any | Security misconfiguration scan |
| `playbook-a04-crypto` | any | Crypto & secrets analysis |
| `playbook-a03-supplychain` | any | Supply chain scan |
| `playbook-a01-access` | `safe`+ | Access control testing |
| `playbook-a07-authn` | `safe`+ | Authentication testing |
| `playbook-a11-ssrf` | `active`+ | SSRF detection |
| `playbook-a14-other` | `active`+ | Smuggling, host-header, cache |
| `playbook-a05-injection` | `active`+ | Injection testing (extended tier) |
| `playbook-a06-design` | `active`+ | Insecure design testing (extended tier) |
| `playbook-a09-opsec` | any | Operational security (extended tier) |
| `playbook-a12-availability` | `active`+ | Availability testing (extended tier) |
| `playbook-a13-llm` | `active`+ | AI/LLM testing (extended tier) |
| `chain-correlate` | any | Cross-category attack chain correlation |
| `chain-complete` | `safe`+ | Auto-loop: parse `suggestedAction` from partial chains, invoke scanners, re-analyze (max 3 iterations) |

**Extended tier** is skipped in `quick` depth. Playbooks are skipped when the budget is exhausted (step status = `budget-exhausted`).

**Chain completion:** The `chain-complete` step takes partial chains from `chain-correlate` (e.g., "IDOR found but no CSRF to prove account takeover"), parses the `suggestedAction` hint, invokes the recommended scanner, and re-runs chain analysis. It loops up to 3 iterations or until no new findings are produced. This turns "possible attack path" into "confirmed exploit chain" autonomously.

**Budget:** Recommended minimums: quick=300s/2000req, standard=1200s/8000req, deep=3600s/15000req.

**Response (additional fields):**

```json
{
  "correlatedChains": {
    "chains": [{ "patternId": "...", "patternName": "...", "chainedSeverity": "critical", "narrative": "..." }],
    "partialChains": [{ "patternId": "...", "suggestedAction": "..." }],
    "chainsFound": 2,
    "partialChainsFound": 5
  },
  "nextActions": [
    { "action": "chain-prove", "workflowId": "csrf-stored-xss-worm", "rationale": "Prove chain: CSRF + Stored XSS → Worm (critical)" },
    { "action": "investigate", "rationale": "Partial chain (IDOR + CSRF → Account Takeover): Run A07 for auth testing" },
    { "action": "run-playbook", "playbookId": "a05-injection", "rationale": "Skipped playbooks may reveal additional findings." }
  ]
}
```

**`nextActions` hints:** `chain-prove` (for provable full chains), `investigate` (for partial chains with suggested follow-ups), `run-playbook` (for skipped extended tier playbooks).

### Cross-Playbook Deduplication

When running multiple playbooks in sequence (e.g., A01 then A02), findings that share the same `(category, endpoint, parameter, method)` are automatically deduplicated. The second playbook's response includes a warning: `"N finding(s) suppressed by cross-playbook deduplication."` This prevents duplicate header/cookie findings when both A01 and A02 scan the same page.

**SARIF dedup handling:** When `format=sarif` and findings are suppressed, the SARIF `run.properties` includes `trowser:deduplication` with `suppressedFindings` count. If *all* findings were suppressed, a synthetic result with `ruleId: "trowser/dedup-info"` and a `suppressions` array (per SARIF 2.1.0 spec) is emitted so CI/CD consumers can distinguish "all deduplicated" from "genuinely clean."

### VPX Finding Structure

Each VPX finding includes OWASP and CWE classifications as first-class fields. The `owasp` field uses **TrowserTwelve** taxonomy (not OWASP 2021 numbering). Key differences: A02=Misconfiguration, A03=Supply Chain, A04=Crypto, **A05=Injection**, A06=Insecure Design, A11=SSRF, A12=Availability, A13=AI/LLM, A14=Other.

```json
{
  "id": "vpx-a02-header-0",
  "kind": "misconfiguration",
  "owasp": "A02",
  "cwe": ["CWE-693"],
  "severity": "medium",
  "title": "Missing/weak: Content-Security-Policy",
  "description": "No Content-Security-Policy header. The page has no CSP protection against XSS.",
  "remediation": "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'",
  "status": "hypothesis",
  "surfaceId": "surf-get-",
  "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
}
```

| Field | Description |
|-------|-------------|
| `owasp` | Trowser-Twelve / OWASP Top Ten ID (A01-A10, A14) |
| `cwe` | Array of applicable CWE identifiers |
| `description` | Detailed explanation of the issue |
| `remediation` | Actionable fix guidance |
| `reference` | OWASP/MDN reference URL (when available from scanner) |

### POST /api/vpx/render

Re-render a stored VPX document without re-running the playbook. Useful for format conversion and "re-show last result".

| Field | Default | Description |
|-------|---------|-------------|
| `vpx` | *(required)* | A VPX 1.0 document (JSON object) |
| `format` | `"markdown"` | `markdown` · `vpx-compact` · `vpx-summary` · `sarif` |

**Response:** The rendered output in the requested format.

---

## Robustness Testing

### POST /api/monkey-test
Random monkey testing (gremlins.js). Blocks navigation during test.

**Safety gate:** Requires `"safetyMode": "active"` — this test performs random clicks, typing, and form submissions that may trigger real server-side actions.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | *(required)* | `"active"` — acknowledge server-side risk. (`confirmBackend: true` accepted as legacy alias) |
| `actions` | 500 | Number of random actions |
| `delay` | 20 | ms between actions |
| `seed` | *(random)* | For reproducibility |

### POST /api/smart-monkey
Systematic robustness: clicks every element, fuzzes forms, crawls links. **Requires a restricted navigation scope** (not `*.*`) — either already set in the app / CLI, via **`POST /api/settings/scope`**, or for this call only via **`scope`** below.

**Safety gate:** Requires `"safetyMode": "active"` — this test systematically interacts with elements and fills forms, which may trigger real server-side actions.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | *(required)* | `"active"` — acknowledge server-side risk. (`confirmBackend: true` accepted as legacy alias) |
| `scope` | *(none)* | Optional. Navigation scope for **this run only** (restores previous guard afterward). Same format as Settings / `--scope`. |
| `followLinks` | true | Crawl links within scope |
| `fuzzForms` | true | Fuzz inputs with edge-case data |
| `maxPages` | 10 | Max pages to visit |
| `maxActionsPerPage` | 100 | Max interactions per page |

### POST /api/interrupter
Fault-injection testing: auto-discovers API endpoints from the network log (raw entries plus optional attack-surface merge), ranks them by relevance (JSON content type, API-like paths, successful responses, sibling host under same registrable domain as the page e.g. `api.` vs `www.`, HTTP method; `socket.io` lightly deprioritized), injects faults via mocks using the **full captured URL** when available (path-only fallback), reloads, and checks for failures (console errors, content changes, error pages). Discovery allows **same registrable host** as the page by default (not only exact origin), and dedupes by `method|host|path`.

**Safety gate:** Requires `"safetyMode": "active"` — reloads the page multiple times; non-mocked requests hit the real server.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | *(required)* | `"active"` — acknowledge server-side risk. (`confirmBackend: true` accepted as legacy alias) |
| `url` | *(auto-discover)* | Target a specific URL (bypasses auto-discovery — works even if URL is not in network log) |
| `method` | *(any)* | Filter by HTTP method |
| `faults` | *(default 5)* | Fault names: `server-error`, `not-found`, `empty-body`, `invalid-json`, `slow-response`. Extra: `unauthorized`, `forbidden`, `rate-limited`, `mutate-response` |
| `maxEndpoints` | 20 | Max endpoints to test (ranked by relevance score) |
| `minRelevanceScore` | 0 | Minimum relevance 0–100; raise to drop low-ranked candidates. **Alias:** `minScore` |
| `mergeAttackSurface` | `true` | Merge paths/methods from `POST /api/security/attack-surface`-style analysis of the same network log |
| `waitForIdle` | false | Wait for network idle before reading the network log for discovery |
| `allowedHosts` | *(page origin)* | Additional hosts to include in auto-discovery beyond current page's origin |
| `cooldownMs` | 0 | Delay in ms between scenarios to avoid rate limits |
| `customFaults` | *(none)* | Array of `{name, status, body?, headers?, delayMs?}` for custom fault definitions |
| `actions` | *(none)* | Actions to replay after each reload for user-triggered endpoints: `[{action, byText/placeholder/selector, text?, value?}]` |
| `restoreUrl` | `true` | Navigate back to the original URL after testing and detect login redirects |

Response includes `finalUrl` (page URL after restoration), `loginRedirectDetected` (true if redirected to login/auth page), and `restoreError` (if restoration failed).

### POST /api/fuzz
Browser-context request fuzzer (Intruder-style). Takes a request template with `§MARKER§` injection points, iterates through payload sets using configurable attack strategies, and flags anomalous responses. Runs `fetch()` inside the browser — real cookies, CSRF tokens, session state.

**Safety gate:** Requires `"safetyMode": "active"` — sends potentially malicious payloads to the target server.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | *(required)* | `"active"` — acknowledge server-side risk. (`confirmBackend: true` accepted as legacy alias) |
| `request` | *(required)* | `{url, method?, headers?, body? or json?}` — template with `§MARKER§` injection points |
| `injectionPoints` | *(required)* | Map of marker names to config: `{"PAYLOAD": {"payloadSet": "sqli-basic"}}` |
| `payloadSets` | *(none)* | Custom sets: `{"name": ["payload1", ...]}` or `{"name": ["built-in"]}` for built-in |
| `attackType` | `sniper` | `sniper`, `battering-ram`, `pitchfork`, `cluster-bomb` |
| `maxConcurrency` | 5 | Max concurrent requests (1-20) |
| `useBrowserCookies` | true | Use browser cookies and session state |
| `stopOnStatus` | *(none)* | Early termination on these status codes |
| `acceptableResponseStatuses` | *(none)* | Status codes that skip status/length anomaly vs baseline (e.g. `[400,403,412]`); 5xx/reflection/timing/error-pattern unchanged |
| `maxRequests` | 1000 | Safety cap on total requests |
| `availabilitySafeDefaults` | `false` | When `true`: `maxRequests=50`, `maxConcurrency=3`, `delayMs=100` unless explicitly overridden |
| `timeoutMs` | 10000 | Per-request timeout |
| `delayMs` | 0 | Delay between request batches |
| `bodySnippetLength` | 500 | Max body snippet in results (0 to exclude) |
| `redirect` | `follow` | Fetch redirect mode: `follow` (default) or **`manual`** — capture 3xx + Location without following (required for open-redirect fuzzing) |
| `payloadGenerators` | *(none)* | Generators: `{"setName": [{"type": "range"/"pattern"/"combine", ...}]}` |

**Built-in payload sets (20):** `json-breaking`, `sqli-basic`, `xss-basic`, **`xss-bypass`** (ordered event-handler / attribute-breakout vectors — same catalog as `trace-input` `autoBypass`), `ssti`, `path-traversal`, `boundary`, `auth-bypass`, `content-type`, `header-injection`, `unicode-edge`, `java-spring`, `integer-overflow`, `nosql-injection`, `ldap-injection`, `xxe`, `ssrf`, **`open-redirect`**, `jwt-manipulation`, `http-method`

**Marker syntax:** Both `§MARKER§` and `{{MARKER}}` are supported (ASCII-safe alternative for shells that struggle with §).

**Payload generators:** Add `payloadGenerators` for programmatic payloads:
- Range: `{"type": "range", "from": 1, "to": 1000}` — numeric brute-forcing
- Pattern: `{"type": "pattern", "template": "user{N}@test.com", "from": 1, "to": 100}`
- Combine: `{"type": "combine", "baseSet": "xss-basic", "encodings": ["url-encode", "base64"]}` — encoding transforms

**Attack types:**
- **sniper:** One injection point at a time, others keep original values
- **battering-ram:** Same payload in all points simultaneously
- **pitchfork:** Parallel iteration (payload sets advance in lockstep)
- **cluster-bomb:** Cartesian product of all payload sets

**Response** includes per-request `payloads` (marker→value), `payloadIndices` (marker→index within payload set for reliable correlation), `injectedUrl`, `injectedBody`, **`location`** (when `redirect: manual`), `flags` (includes **`OpenRedirect`** when Location points off-site), and `flagDetails`. Reflection flags may include context notes (e.g. `javascript:` URI reflected in text content, not a URL attribute).

### GET /api/fuzz/payloads
List built-in payload sets with sample payloads and counts.

---

## Peer Management (Cross-Instance Testing)

Register and interact with other Trowser instances on localhost for N-body authorization testing. Each peer has its own browser session (cookies, storage, auth state). Peer endpoints **bypass the gate** — they are HTTP proxies and do not touch the local WebView2.

### POST /api/peer/register
Register a peer Trowser instance. Validates that `baseUrl` is localhost and pings the peer.

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique peer name (e.g. `"attacker"`, `"tenant-b"`) |
| `baseUrl` | Yes | Peer API base URL (e.g. `"http://localhost:6924"`). Must be localhost. |
| `apiKey` | No | API key for the peer instance |

Response: `{ registered, name, baseUrl, alive, sessionName, pingError }`.

### DELETE /api/peer/{name}
Unregister a peer by name.

### GET /api/peers
List all registered peers with health status and session names.

Response: `{ peers: [{ name, baseUrl, alive, sessionName }], count }`.

### POST /api/peer/fetch
**The workhorse for cross-identity testing.** Send an HTTP request through a peer's browser session — the request uses the **peer's** cookies, auth tokens, and session state. Compare responses across identities to detect BOLA/IDOR.

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | Yes | Registered peer name |
| `url` | Yes | Request URL (absolute or relative to peer's current page) |
| `method` | No | HTTP method (default `GET`) |
| `headers` | No | Request headers object |
| `json` | No | JSON body (auto-serialized) |
| `body` | No | Raw string body |
| `timeout` | No | Request timeout in ms (default 30000) |
| `ensureOrigin` | No | Auto-navigate peer to the target URL's origin if needed, so cookies are sent correctly (default `false`) |

Response: proxied response from the peer's `POST /api/fetch` — includes `ok`, `status`, `headers`, `body`.

**Gate-free design:** `peer/fetch` uses the peer's `POST /api/fetch-direct` endpoint (server-side HTTP with browser cookies) instead of the gated `POST /api/fetch`. This completely avoids gate contention on the peer — requests never block waiting for the peer's WebView2 gate.

**Example — BOLA test:**
```json
// On instance A (admin), after registering instance B (attacker):
POST /api/peer/fetch
{ "peer": "attacker", "url": "https://app.example.com/api/orders/123", "ensureOrigin": true }
// Compare the attacker's response with admin's own:
POST /api/fetch
{ "url": "https://app.example.com/api/orders/123" }
// If both return 200 with the same body → BOLA suspected
```

### POST /api/peer/state
Get `GET /api/state` from a peer (URL, title, interactive elements).

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | Yes | Registered peer name |

### POST /api/peer/navigate
Navigate a peer to a URL (calls `POST /api/navigate` on the peer).

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | Yes | Registered peer name |
| `url` | Yes | URL to navigate to |

### POST /api/peer/screenshot
Take a screenshot of a peer's current page.

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | Yes | Registered peer name |
| `format` | No | `jpeg` (default) or `png` |
| `quality` | No | JPEG quality 1–100 (default 60) |

### GET /api/info (updated)
Now also returns `sessionName` — the named session this instance is using (from `--session`).

---

## Authorization Testing

Automated BOLA/IDOR detection and access-control boundary mapping. These endpoints use the browser's real session (cookies, auth tokens) for requests.

### POST /api/authz/probe
**Batch authorization boundary scanner.** Test whether the current session has access to a list of endpoints in a single call. Auto-classifies responses.

| Field | Required | Description |
|-------|----------|-------------|
| `endpoints` | Yes | Array of endpoints — plain URL strings (→ GET) or objects with `url`, `method?`, `headers?`, `json?`, `body?` |
| `classify` | No | Auto-classify: 2xx=`allowed`, 4xx=`denied`, 5xx=`error` (default `true`) |
| `ensureOrigin` | No | Navigate browser to the target origin before probing, so cookies are sent correctly (default `false`) |

**Response:**
```json
{
  "results": [
    {"url": "...", "method": "GET", "status": 200, "classification": "allowed", "bodyLength": 1234, "bodyHash": "a1b2c3d4e5f67890"},
    {"url": "...", "method": "GET", "status": 401, "classification": "denied", "bodyLength": 55, "errorSnippet": "Unauthorized"},
    {"url": "...", "method": "PUT", "status": 500, "classification": "error", "bodyLength": 200, "errorSnippet": "NullPointerException..."}
  ],
  "summary": {"total": 3, "allowed": 1, "denied": 1, "errors": 1}
}
```

### POST /api/authz/diff
**Cross-identity authorization comparison — the BOLA killer.** Runs the same set of endpoints on both the local session AND a registered peer's session, producing a structured diff with auto-classification.

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | One of peer/peers | Single registered peer name (legacy) |
| `peers` | One of peer/peers | Array of registered peer names — runs diff against each |
| `endpoints` | Yes | Array of URL strings or `{ url, method?, headers?, json?, body? }` objects |
| `includeBody` | No | Include full response bodies in results (default `false`) |
| `includeBodyOnMismatch` | No | Include bodies only when local and peer responses differ (default `false`) |
| `ensureOrigin` | No | Auto-navigate peer to the target origin before fetching (default `true`) |
| `leakTokens` | No | Array of strings to search for in peer responses to detect data leaks (e.g. patient names, user IDs) |
| `bodyMatch` | No | Response comparison: `{ strategy?: "exact"|"normalizedJson"|"structural", ignoreFields?: string[] }`. `normalizedJson` strips volatile fields before hashing (defaults include `timestamp`, `requestId`, `sessionId`, etc.) |
| `ignoreFields` | No | Shorthand: enables `normalizedJson` with these field names when `bodyMatch` is omitted |
| `structuralMatch` | No | Shorthand: `true` sets `strategy: structural` (compare JSON shape only — use cautiously) |

**Auto-classification logic:**
| Local | Peer | Finding |
|-------|------|---------|
| 200 + same body | 200 + same body | `BOLA_SUSPECTED` ⚠️ |
| 200 | 200 + different body | `FILTERED_RESPONSE` (check manually) |
| 200 | 200 via redirect to login/access-denied page | `REDIRECT_DENIED` ✅ (common with ASP.NET WebForms, Spring Security) |
| 200 | 401/403 | `PROPERLY_DENIED` ✅ |
| 200 | 500 | `ERROR_BEFORE_AUTH` ⚠️ |
| 401/403 | 401/403 | `DENIED_BOTH` ℹ️ |

Each comparison now includes **redirect info**: `redirected` (boolean) and `finalUrl` (the URL after redirects, when different from the requested URL). This is especially useful for server-side redirect-based authorization (302→login page).

**Response:**
```json
{
  "peer": "attacker",
  "comparisons": [
    {
      "url": "https://app.example.com/api/facility/XYZ",
      "method": "GET",
      "local": {"status": 200, "bodyLength": 549, "bodyHash": "a1b2c3d4e5f67890", "redirected": false, "finalUrl": null},
      "peer": {"status": 200, "bodyLength": 549, "bodyHash": "a1b2c3d4e5f67890", "redirected": false, "finalUrl": null},
      "match": true,
      "finding": "BOLA_SUSPECTED"
    },
    {
      "url": "https://app.example.com/api/services?hsaid=XYZ",
      "method": "GET",
      "local": {"status": 200, "bodyLength": 1623, "bodyHash": "..."},
      "peer": {"status": 401, "bodyLength": 55, "bodyHash": "..."},
      "match": false,
      "finding": "PROPERLY_DENIED"
    }
  ],
  "summary": {
    "totalEndpoints": 2, "bolaSuspected": 1, "filteredResponse": 0,
    "properlyDenied": 1, "deniedBoth": 0, "errorBeforeAuth": 0, "errors": 0
  }
}
```

### POST /api/authz/fuzz
**Parameter fuzzing with crash detection.** Takes a URL template with `{param}` placeholders and an array of parameter sets. Substitutes each set, fires the request, and classifies responses. Detects server crashes (NullPointerException, stack traces, SQL errors).

| Field | Required | Description |
|-------|----------|-------------|
| `endpoint` | Yes | URL template with `{param}` placeholders, e.g. `https://app.com/api/case/{hsaId}/items` |
| `method` | No | HTTP method (default `GET`) |
| `parameterSets` | Yes | Array of objects: `{ paramName: "value", body?: "...", headers?: {...} }`. `body` is the request body, other keys are URL substitutions. |
| `headers` | No | Default headers for all requests |
| `classify` | No | Auto-classify responses (default `true`) |
| `detectCrashPattern` | No | Detect crash patterns (NullPointerException, stack traces, etc.) in 5xx responses (default `true`) |

**Response:**
```json
{
  "endpoint": "https://app.com/api/case/{hsaId}/items",
  "method": "POST",
  "results": [
    {"url": "https://app.com/api/case/VALID-ID/items", "status": 200, "classification": "allowed", "bodyLength": 1234},
    {"url": "https://app.com/api/case/NONEXIST/items", "status": 500, "classification": "error", "crash": true, "errorSnippet": "java.lang.NullPointerException at..."}
  ],
  "summary": {"total": 2, "allowed": 1, "denied": 0, "errors": 1, "crashes": 1}
}
```

### POST /api/authz/boundary
**Authorization boundary testing.** Tests a URL with authorized vs unauthorized parameter values and auto-detects when unauthorized access is granted. Compares unauthorized responses against the authorized baseline.

Accepts **legacy single-endpoint fields** or **`endpoints[]`** for batch tests. Each endpoint object uses the same base shape as `authz/diff` (`url`, `method?`, `headers?`, `json?`, `body?`) plus boundary fields.

| Field | Required | Description |
|-------|----------|-------------|
| `endpoint` / `url` | One of | Legacy: URL template with `{parameter}` placeholder |
| `endpoints` | One of | Batch: array of `{ url, parameter, authorizedValues, unauthorizedValues, method?, headers?, json?, body?, bodyTemplate?, peer? }` |
| `parameter` | Yes* | The placeholder name in the URL (*per endpoint when using `endpoints[]`) |
| `authorizedValues` | Yes* | Values the current session SHOULD have access to (establishes baseline) |
| `unauthorizedValues` | Yes* | Values the current session should NOT have access to |
| `method` | No | HTTP method (default `GET`) |
| `peer` | No | Run unauthorized tests through a peer's session instead of the local one |
| `headers` | No | Request headers |
| `json` | No | JSON request body |
| `body` | No | Raw request body |
| `bodyTemplate` | No | Request body template with `{parameter}` placeholder |
| `bodyMatch` | No | Baseline comparison: `{ strategy?: "exact"|"normalizedJson"|"structural", ignoreFields?: string[] }` |
| `ignoreFields` | No | Shorthand for `normalizedJson` with custom field names |
| `structuralMatch` | No | Shorthand: compare JSON structure only |

**Auto-classification:**
| Finding | Meaning |
|---------|---------|
| `PROPERLY_DENIED` | 401/403 — access correctly denied ✅ |
| `IDENTICAL_TO_AUTHORIZED` | Same response as authorized baseline — BOLA suspected ⚠️ |
| `ACCESS_GRANTED` | 200 but different body — manual review needed |
| `ERROR` | Server error |

**Response:**
```json
{
  "endpoint": "https://app.com/secure/facility/{id}",
  "parameter": "id",
  "baseline": [{"value": "AUTHORIZED-ID", "status": 200, "bodyLength": 549, "bodyHash": "abc123"}],
  "findings": [
    {"value": "UNAUTHORIZED-ID", "url": "...", "status": 200, "bodyLength": 549, "bodyHash": "abc123", "finding": "IDENTICAL_TO_AUTHORIZED", "matchesAuthorizedResponse": true},
    {"value": "NONEXIST-ID", "url": "...", "status": 403, "finding": "PROPERLY_DENIED", "matchesAuthorizedResponse": false}
  ],
  "summary": {"authorizedCount": 1, "unauthorizedCount": 2, "properlyDenied": 1, "accessGranted": 0, "identicalToAuthorized": 1, "errors": 0}
}
```

### POST /api/fetch-direct
**Gate-free server-side fetch with browser cookies.** Makes an HTTP request server-side using `HttpClient` with cookies extracted from the browser's CookieManager (including HttpOnly cookies). Unlike `POST /api/fetch` (which runs `fetch()` inside WebView2 and requires the gate), this endpoint bypasses the gate entirely. Used internally by `peer/fetch` to avoid deadlocks.

Same request/response format as `POST /api/fetch`.

### GET /api/session/identity

**Live session introspection** (renamed from `GET /api/identity`). Returns session name, domain, redacted cookie previews, storage tokens, and inferred auth mechanism. **Gate-free.**

**Response `data`:** `sessionName`, `domain`, `currentUrl`, `cookieCount`, `cookies`, `inferredTokens?`, `inferredIdentity?`

Supported auth mechanisms: `shibboleth`, `java-session`, `aspnet`, `oauth`, `jwt-cookie`, `session-cookie`, `storage-token`.

### GET /api/identities

Catalog of **captured** identity snapshots (metadata only). **Gate-free.**

**Response `data`:** `count`, `identities[]` (each with `name`, `capturedAt`, `domain`, `inferredMechanism`, `cookieCount`, etc.)

### GET /api/identity/{name} · DELETE /api/identity/{name}

**GET** — Full snapshot (redacted by default). Query `?reveal=true` for local debug with full values.

**DELETE** — Remove stored snapshot.

### POST /api/identity/capture

Snapshot cookies, localStorage, sessionStorage, and optional auth headers from network log. Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `name` | — | Identity name (required) |
| `includeAuthHeaders` | `true` | Capture Authorization / API-key headers from network log |
| `authHeaderMaxAgeMinutes` | `30` | Max age of headers to include |

Stored under `%LocalAppData%\Trowser\Identities\{name}\`.

### POST /api/identity/apply

Install a captured identity into `self` or a registered `peer`. Clears cookies/storage first, then applies snapshot. Blocked in safe mode.

| Field | Description |
|-------|-------------|
| `name` | Captured identity name (required) |
| `target` | `self` (default) or `peer` |
| `peer` | Registered peer name when `target=peer` |
| `navigateTo` | Optional URL to open after apply |
| `verify` | Optional `{ url, expectStatus?, method?, headers?, body?, timeoutMs? }` liveness probe |

### POST /api/peer/identity/apply

Forward identity apply to a registered peer (`peer` + same fields as apply except target is always self on peer).

### POST /api/identity/handoff · GET /api/identity/handoff

SSO/MFA handoff — human completes login in GUI, Trowser auto-captures on cookie/storage/liveness delta.

**POST** `action=start` (default): `{ name, timeoutMs?, livenessUrl? }` → `{ status: "waiting", expiresAt, ... }`

**GET** or **POST** `action=status`: `{ name, autoCapture? }` → `{ status: "waiting"|"captured"|"expired", ... }`

**POST** `action=cancel`: `{ name }`

**MCP:** `browser_session_identity`, `browser_identities`, `browser_identity_capture`, `browser_identity_apply`, `browser_identity_handoff`

**Legacy:** `GET /api/identity` returns **410** with pointer to `/api/session/identity`.

---

## MCP Protocol

**Endpoint:** `POST http://localhost:6923/mcp` (Streamable HTTP, JSON-RPC 2.0)

```json
{"mcpServers": {"trowser": {"url": "http://localhost:6923/mcp"}}}
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `browser_snapshot` | Page state: URL, title, headings, interactive elements, errors |
| `browser_diff_state` | Diff two refGeneration snapshots (added/removed elements, text/value, URL/title, new errors) |
| `browser_navigate` | URL (`url`) or history (`action`: back / forward) |
| `browser_force_navigate` | `url`, optional `terminateScripts` — CDP recovery; MCP bypasses gate for this tool |
| `browser_go_back` | History: back |
| `browser_go_forward` | History: forward |
| `browser_click` | Click element (left/right/middle, single/double) |
| `browser_type` | Type into input (clears first) |
| `browser_upload` | File input: `path`, `paths`, or `base64` + optional `fileName`; optional `submit` (blocked in safe mode) |
| `browser_select_option` | Select dropdown option |
| `browser_hover` | Hover over element |
| `browser_press_key` | Keyboard key press |
| `browser_scroll` | Scroll page or element into view |
| `browser_take_screenshot` | Screenshot as inline base64. Supports `format` (png/jpeg), `quality`, ref/selector, padding |
| `browser_screenshot_compare` | Visual diff: compare two screenshots, highlight pixel changes in red overlay |
| `browser_text` | Element inner text (pierces shadow DOM) |
| `browser_extract` | Extract structured data from tables/repeating elements |
| `browser_page_text` | All visible page text |
| `browser_page_text_all` | All text nodes including hidden; one line per segment |
| `browser_page_text_screen_reader` | Alt, aria-*, title, SVG title/desc (`[kind]` prefixes) |
| `browser_page_source` | Full HTML source |
| `browser_execute_js` | Run JavaScript |
| `browser_accessibility` | WCAG audit (axe-core) |
| `browser_tab_order` | Keyboard tab-order verification (real Tab/Shift+Tab) |
| `browser_performance` | Web Vitals measurement |
| `browser_resource_snapshot` | Resource snapshot: JS heap, DOM nodes, listeners, WebSockets (CDP). Optional `rememberBaseline` |
| `browser_resource_compare` | Compare saved baseline to current page after your own actions |
| `browser_resource_probe` | Repeat actions or reloads with GC; findings for heap/listener/DOM growth |
| `browser_security` | JS CVE scan (Retire.js) |
| `browser_security_headers` | HTTP security header analysis |
| `browser_validate_html` | HTML validation |
| `browser_compatibility` | Backward compatibility analysis |
| `browser_audit_all` | Full health audit (same as POST /api/audit-all) |
| `browser_surpriseme` | Run a random non-destructive quicktest (same as POST /api/surpriseme) |
| `browser_check_links` | Check links for broken URLs and redirects |
| `browser_security_xss` | DOM XSS pattern audit |
| `browser_structured_text` | Structured text extraction for proofreading |
| `browser_consistency` | GUI visual consistency & image optimization audit |
| `browser_third_party` | Third-party resource inventory |
| `browser_mixed_content` | Mixed content detection (HTTP on HTTPS) |
| `browser_security_storage` | Web storage security audit (tokens, PII, JWTs, stored XSS risk) |
| `browser_monkey_test` | Random monkey testing (requires `safetyMode: "active"`) |
| `browser_smart_monkey` | Smart robustness testing; optional `scope` for this run only (requires `safetyMode: "active"`) |
| `browser_interrupter` | Fault-injection testing: ranked discovery (default `maxEndpoints` 20), `mergeAttackSurface`, `minRelevanceScore` / `minScore`, sibling-host discovery, customFaults, actions, mutate-response, cooldown (requires `safetyMode: "active"`) |
| `browser_fuzz` | Browser-context request fuzzer: §MARKER§ injection points, built-in payload sets (sqli, xss, ssti, **open-redirect**, etc.), attack types (sniper/battering-ram/pitchfork/cluster-bomb), anomaly detection; use **`redirect: manual`** for open-redirect testing (requires `safetyMode: "active"`) |
| `browser_security_csrf` | CSRF assessment: missing/invalid token tests, Referer bypass, JSON API probes, **SameSite cookie context**, **custom-header simple-request probes** (`safetyMode: "active"`; blocked in safe mode) |
| `browser_security_path_traversal` | Path traversal: **query** mode (fuzz query params from log or `urls`) or **path** mode (`mode`, `basePath`, `pathBases`; requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ssrf_scan` | SSRF scanner: internal IPs, cloud metadata, protocol handlers, callback probes; discovery, **`endpointHints`**, or request template mode; uses `redirect: manual` on redirect-like params (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_open_redirect_scan` | Open redirect scanner (CWE-601): probes redirect/url/next params with `redirect: manual`, checks Location for off-site redirects; **`endpointHints`** for params without query in URL (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_methods` | HTTP methods testing: probes GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE and flags security issues |
| `browser_security_smuggling` | HTTP Request Smuggling detection: raw TCP probing for CL-TE, TE-CL, TE-TE obfuscation, CL-CL duplicate headers, and header normalization weaknesses. Timing-based detection — no actual smuggling. Includes infrastructure fingerprinting (proxy/CDN detection). Requires `safetyMode: "active"`; blocked in safe mode. |
| `browser_security_host_header` | Host header injection scanner: raw TCP probing for Host override, X-Forwarded-Host, duplicate Host, port manipulation, absolute-URL requests. Detects reflected poisoned host in redirects, links, and body. Auto-discovers reset/invite endpoints from network log. Requires `safetyMode: "active"`; blocked in safe mode. |
| `browser_security_shadow` | Security Shadow Mode: enable/disable/query ambient continuous security analysis |
| `browser_firewall_test` | Client-side firewall testing: active verification of CSP, SRI, iframe sandbox, Permissions-Policy (requires `safetyMode: "active"`) |
| `browser_trace_input` | Input→Network→DOM tracing: sources `form`, `url-query`, `url-hash`, `url-path`; auto URL probes when form filters input (`probeUrlSources`); `autoBypass`; `monitorSinks` (requires `safetyMode: "active"`) |
| `browser_security_tech_stack` | Tech stack fingerprinting: servers, frameworks, JS libraries, WAFs, CDNs, CMSes from headers, cookies, DOM, script analysis |
| `browser_security_sqli_scan` | Lightweight SQLi probe: markers in `request`, baseline + small payload set; optional `useBackendFetch` / `includeBrowserCookies` for Angular/Zone.js (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_sqli_login_sweep` | SQLi login bypass sweep on common login paths (form + JSON) (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_nosql_scan` | NoSQL operator injection on login/search endpoints (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ldap_scan` | LDAP filter injection: baseline 401/403 → filter break-out on login URLs (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ssti_scan` | SSTI scan: arithmetic 49/56 + template engine errors; sparse-traffic scaffold (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ssti_polyglot_scan` | Fast GET polyglot SSTI probe `${7*7}{{7*7}}…` (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ssti_stored_scan` | Stored SSTI: POST profile field → GET readback for 13289 marker (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_prototype_pollution_scan` | Server-side prototype pollution POST+GET canary verify (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_csti_scan` | Client-side template injection DOM scan (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_cmd_canary` | Command injection / RCE canaries on injectable params (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_auto_scan` | Automated injection pipeline: SQLi, SSTI (+ polyglot/stored/scaffold), NoSQL, LDAP, prototype pollution, IDOR, CSRF, SSRF, … (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_js_audit` | Fetch `script[src]` assets, heuristic creds/internal-url/debug scan (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_parser_probe` | Parser differential: Content-Type/body-shape matrix on JSON endpoints (requires `safetyMode: "active"`) |
| `browser_security_deserialization_scan` | Deserialization: node-serialize timing, YAML DoS, Java/PHP stubs (requires `safetyMode: "active"`) |
| `browser_security_file_upload_scan` | File upload validation + optional upload XXE (requires `safetyMode: "active"`) |
| `browser_security_nextjs_rsc_scan` | Next.js RSC Flight deserialization probe (requires `safetyMode: "active"`) |
| `browser_security_race_condition_scan` | TOCTOU race burst on single-use POST endpoints (requires `safetyMode: "active"`) |
| `browser_security_captcha_replay_scan` | CAPTCHA token replay / broken anti-automation (requires `safetyMode: "active"`) |
| `browser_security_rate_limit_audit` | A12 rate-limit audit: sequential + burst, emits missing/weak/present (requires `safetyMode: "active"`) |
| `browser_security_redos_scan` | ReDoS timing oracle on injectable params (requires `safetyMode: "active"`) |
| `browser_security_body_size_limit_scan` | Body-size tiers 1 KB–1 MB on POST endpoints (requires `safetyMode: "active"`) |
| `browser_security_workflow_skip_scan` | Late-stage workflow step-skip probe (requires `safetyMode: "active"`) |
| `browser_security_session_fixation_scan` | Session fixation: cookie unchanged after login (requires `safetyMode: "active"`) |
| `browser_security_password_reset_weak_scan` | Security-question password reset bypass (requires `safetyMode: "active"`; `confirmDestructive` to change password) |
| `browser_security_account_enumeration_scan` | Account enumeration: REST leak + login differential + register probe (requires `safetyMode: "active"`) |
| `browser_security_logout_invalidation_probe` | Logout invalidation: replay session after logout (requires `safetyMode: "active"`) |
| `browser_security_supply_chain_scan` | Supply chain: Retire.js CVEs, SRI, manifest fetch + OSV, CI/CD exposure, JS bundle fingerprinting, optional CVE reachability (`safetyMode: "active"` for reachability) |
| `browser_security_osv_check` | OSV.dev lookup for raw manifest body (offline parser test; gate-free) |
| `browser_security_jwt_analyze` | Decode/analyze JWTs from cookies + storage; alg, exp, sensitive claims (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_brute_force` | Failed login lockout test or password spray (`usernames[]`; requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_idor_scan` | Multi-id + multi-method IDOR (network method inference, PUT/PATCH/DELETE fallbacks; requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_mass_assignment_scan` | JSON mass-assignment reflection probe (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_mass_assignment_patch` | PATCH/PUT self-promote probe with persistence verify (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_mass_assignment_register` | Registration mass-assignment scaffold (requires `safetyMode: "active"` + `confirmDestructive`; blocked in safe mode) |
| `browser_security_bfla_probe` | BFLA admin POST/PUT probe with current session (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_response_field_diff` | JSON field diff between two captured identities (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_authz_role_matrix` | Role×endpoint authorization matrix (requires captured `identities[]`; allowed in safe mode) |
| `browser_security_verify` | Exploit verifier: optional inject → navigate with `renderInjection` (query/hash/path) or `§MARKER§` templates; `skipInjection` for DOM XSS; `fragmentEncode`/`queryEncode` (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_callbacks` | Out-of-Band interaction detection: monitor for callback domain requests (blind XSS, DOM SSRF) |
| `browser_security_chain_analyze` | Attack chain discovery: analyzes shadow/auto-scan findings to find multi-step exploit chains (CSRF→XSS worm, CORS+info-leak→token theft, etc.). Returns full chains with severity upgrades and partial chains with suggested next tests. |
| `browser_security_chain_patterns` | List, add, or remove attack chain patterns. 17 built-in patterns covering account takeover, data breach, session hijack, worm propagation, and more. |
| `browser_websocket_connections` | List tracked WebSocket connections for the active tab (URL, state, frame counts, handshake status) |
| `browser_websocket_messages` | Query WebSocket frames with optional filtering by connection, direction, search text, and limit |
| `browser_websocket_send` | Send message on active WebSocket via page hook (blocked in safe mode) |
| `browser_websocket_close` | Close active WebSocket via page hook (blocked in safe mode) |
| `browser_security_websocket_audit` | WebSocket security audit: checks origin validation, authentication, TLS, sensitive data in frames, input validation, message type surface |
| `browser_security_cswsh_test` | Cross-Site WebSocket Hijacking test: raw TCP handshake from attacker origin with victim cookies. Supports `preset: graphql-ws`. Shadow mode auto-probes new connections. |
| `browser_console` | Console messages |
| `browser_network` | Network traffic (with filters) |
| `browser_network_clear` | Clear network traffic log |
| `browser_clear_all` | Reset all test state (console, network, cookies, mocks, intercepts, assertions, storage) |
| `browser_wait` | Wait for element |
| `browser_assert_text` | Assert page text |
| `browser_assert_element` | Assert element visibility/text/attribute/count |
| `browser_assert_url` | Assert current URL |
| `browser_assert_title` | Assert page title |
| `browser_handle_dialog` | Configure dialog handling |
| `browser_dialog` | Get last dialog info |
| `browser_tabs` | List open tabs |
| `browser_new_tab` | Open new tab |
| `browser_close_tab` | Close tab |
| `browser_switch_tab` | Switch active tab |
| `browser_viewport` | Set viewport size |
| `browser_fetch` | Send HTTP request from browser context (cookies/auth included) |
| `browser_mock` | Manage network mocks |
| `browser_intercept` | Manage request breakpoints |
| `browser_webmcp_tools` | Detect WebMCP tools |
| `browser_webmcp_call` | Call WebMCP tool |
| `browser_network_throttle` | Simulate slow network |
| `browser_wait_for_network` | Wait for specific network request |
| `browser_storage` | Read/write localStorage/sessionStorage |
| `browser_inspiration` | Get a random testing inspiration message |
| `browser_journal_add` | Add a note to the test journal (observations, bugs, strategy). Supports `tags` and auto-captures page `url`. |
| `browser_journal_get` | Get journal entries (with `since`, `last`, `type`, `source`, `tag` filters) |
| `browser_peer_register` | Register a peer Trowser instance for cross-instance security testing: `name`, `baseUrl` (localhost), optional `apiKey` |
| `browser_peers` | List all registered peer instances with health status and session names |
| `browser_peer_fetch` | **Cross-identity fetch**: send a request through a peer's browser session (uses peer's cookies/auth). The workhorse for BOLA/IDOR testing. Fields: `peer`, `url`, `method`, `headers`, `json`, `body`, `timeout` |
| `browser_peer_state` | Get page state (URL, title, elements) from a peer instance |
| `browser_peer_navigate` | Navigate a peer instance to a URL |
| `browser_peer_screenshot` | Take a screenshot of a peer instance's page |
| `browser_peer_unregister` | Remove a peer from the registry |
| `browser_authz_probe` | Batch authorization boundary scanner — test access to multiple endpoints |
| `browser_authz_diff` | Cross-identity authorization comparison with auto-classification (BOLA detection) |
| `browser_authz_fuzz` | Parameter fuzzing with crash detection (NullPointerException, stack traces) |
| `browser_authz_boundary` | Authorization boundary testing — authorized vs unauthorized parameter values |
| `browser_session_identity` | Live session identity introspection (cookies, auth mechanism) |
| `browser_identities` | List captured identity snapshots |
| `browser_identity_capture` | Capture portable identity snapshot (blocked in safe mode) |
| `browser_identity_apply` | Apply captured identity to self or peer (blocked in safe mode) |
| `browser_identity_handoff` | SSO/MFA handoff with auto-capture on login delta |

MCP tools accept the same element targeting: `ref`, `selector`, `role`+`name`, `label`, `text`, `placeholder`, `testId`.
