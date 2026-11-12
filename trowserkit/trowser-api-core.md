# Trowser REST API — Core

The endpoints you need for everyday web testing: look at the page, act on it, wait, assert, read console and network, call HTTP APIs, run the quality audits, record findings. It is a condensed subset of **[trowser-api-reference.md](trowser-api-reference.md)**, which has every endpoint, every parameter, and the response shapes in full. Use the full reference when a field you need is not listed here.

**Base URL:** `http://localhost:6923` · **Auth:** `Authorization: Bearer <api-key>` on every call except `GET /api/ping` · **Bodies:** JSON (`Content-Type: application/json`)

---

## Basics

### Starting and calling

- Enable the API in Trowser's status bar, or run headless: `Trowser.exe --serve --api --api-port 6923 --api-key <key>`.
- Port in use → Trowser tries the next 9 ports. `--session <name>` isolates cookies/storage/cache; `--ephemeral` uses a throwaway session.
- From PowerShell use `Invoke-RestMethod` (`irm`), not `curl` (an alias of `Invoke-WebRequest`):

```powershell
$h = @{ Authorization = "Bearer <api-key>" }
irm http://localhost:6923/api/state -Headers $h
irm http://localhost:6923/api/click -Method Post -Headers $h -ContentType "application/json" -Body '{"ref": 5}'
```

### Responses

Every response is `{"success": true, "data": {...}}` or `{"success": false, "error": "..."}`.

| Status | Meaning |
|--------|---------|
| 400 | Missing or invalid field |
| 401 | Missing or wrong API key |
| 403 | Blocked by safe mode (`--safe`) |
| 404 | Unknown endpoint |
| 499 | Cancelled by `POST /api/abort` |
| 500 | Element not found, script error, etc. |
| 503 | Server busy with another call (`blockedBy`, `dialogPending` tell you why) |
| 504 | Timed out (navigation or JS exceeded its limit) |

Calls are serialized: one gated operation at a time. Endpoints marked **gate-free** below (journal, console, network, assertions, dialog) answer even while another call is running.

### Safety

- **`--safe`** (CLI) blocks anything that runs code or changes state outside normal browsing: `execute-js`, `execute-script`, `fetch` (+ batch), `upload`, mocks, cookie/storage writes, header overrides, and active security probes. Those return **403**.
- **`safetyMode`** in the request body controls how invasive a security probe may be: `passive` (no outbound probes) → `safe` (default; GET/HEAD/OPTIONS only) → `active` (all verbs, may create test data) → `aggressive` (high volume). Probes that can change server state run only at `active` or above.
- Only test systems you are authorized to test.

---

## Element addressing

Every action that targets an element accepts **one** of these:

```json
{"ref": 5}
{"selector": "#submit-btn"}
{"role": "button", "name": "Submit"}
{"label": "Email address"}
{"byText": "Sign in"}
{"placeholder": "Search..."}
{"testId": "submit-btn"}
{"ref": 3, "frame": "iframe#child-frame"}
```

- **Refs** come from `GET /api/state` → `interactiveElements[].ref`. Prefer them. Hidden elements have `ref: -1`.
- **Refs go stale** when the DOM changes. Actions then return `staleRefWarning`; re-fetch `/api/state`. Pass `refGeneration` with an action to get a hard error instead of a warning.
- **`byText`** is case-insensitive and whitespace-normalized, and also matches the accessible name (including `<input type=submit>` values).
- **`text` is not a locator on `/api/type`** — there it is the content to type. Use `byText` to locate by visible text.
- **`frame`** (frameId, iframe `name`, or CSS selector of the `<iframe>`) scopes the target to an iframe. `GET /api/frames` lists them.
- All actions auto-wait up to 5 s for the element to be visible and enabled. Override with `"timeout": <ms>`.

---

## Core loop

1. `GET /api/state` — URL, title, text, interactive elements with refs, console and network errors.
2. Act by ref: `POST /api/click`, `/api/type`, `/api/select`, `/api/key`.
3. Wait if the page loads asynchronously: `/api/wait`, `/api/wait-for-idle`, `/api/wait-for-network`.
4. Re-read `GET /api/state` (or `POST /api/diff-state`) to see what changed.
5. Check `GET /api/console` and `GET /api/network?errors=true` for failures the page did not show.
6. Assert (`/api/assert/*`) and record findings (`POST /api/journal`).

---

## Page state

### GET /api/state
**The main endpoint.** Returns `url`, `title`, `pageText` (first 3000 chars), `headings`, `interactiveElements` (with `ref`, role, label, `checked` for checkboxes/radios), `frames[]`, `imageSummary`, `consoleErrors`, `networkErrors`, `assertionSummary`, `refGeneration`.

Query parameters (all optional): `fullText=true` (untruncated text) · `visible=false` (include hidden elements) · `selector=<css>` (scope to a container) · `frame=<id|name|css>` (refs inside an iframe) · `tag=input` · `type=checkbox` · `q=<text>` (filter elements by label/text) · `limit=<n>` · `sections=url,title,interactiveElements`. Filtering never renumbers refs.

### Related reads

| Endpoint | Returns |
|----------|---------|
| `GET /api/interactive` | Interactive elements only: `count`, `refGeneration`, `elements` (lighter than `/api/state`) |
| `POST /api/state/refresh` | Forces a full rescan; use when `/api/state` looks stale after DOM changes |
| `POST /api/diff-state` | `{before, after}` refGenerations → `elementsAdded`, `elementsRemoved`, `textChanged`, `urlChanged`, `titleChanged`, `newConsoleErrors`, `newNetworkErrors` |
| `POST /api/state/enrich` | `{refs: [..], fields: ["text","href","value","disabled",...]}` → those fields for many refs in one call |
| `GET /api/info` | Version, current URL/title, navigation scope, MCP pack, counts |
| `GET /api/frames` | iframe list `{frameId, name, url, sameOrigin, parentFrameId}` |
| `GET /api/page-text` | Visible text (`innerText`) |
| `GET /api/page-text/all` | Every text node, including hidden and shadow DOM |
| `GET /api/page-text/screen-reader` | `alt`, `aria-label`, `aria-labelledby/describedby`, `title`, each line prefixed `[kind]` |
| `POST /api/page-text/structured` | `headings`, `paragraphs`, `links`, `buttons`, `labels`, `images`, `wordCount` (for proofreading) |
| `GET /api/source` | Full HTML (`outerHTML`) |
| `GET /api/ping` | Health, no auth: `busy`, `currentOperation`. No URL or title |

### Screenshots

`GET /api/screenshot` saves a file and returns `{path, format}` (never raw bytes). Params: `format=png|jpeg`, `quality=80`, `base64=true` (also return the image inline), `ref=N` or `selector=<css>` (one element), `padding`, `filename`. For an LLM to look: `?format=jpeg&quality=60&base64=true`.

`POST /api/screenshot/compare` — `before` (path or base64, required), `after` (omit = capture now), `threshold` (0–255, default 30) → `diffPercent`, `changedPixels`, `match`, `diffPath`.

---

## Navigation

### POST /api/navigate
`{"url": "https://example.com"}` (scheme defaults to `https://`) or `{"action": "back"|"forward"}`. Optional `reload: true` (real refresh; may re-POST a form), `ignoreCertificateErrors: true`.

A successful response means the navigation event finished — **not** that redirects (SSO/OAuth/SAML) settled or an SPA rendered. Follow with `wait-for-final-navigation` and/or `wait-for-idle`, then `GET /api/state`.

| Endpoint | Body (defaults) | Purpose |
|----------|-----------------|---------|
| `POST /api/go-back` / `POST /api/go-forward` | — | One history step |
| `POST /api/wait-for-final-navigation` | `quietPeriod` 500, `timeout` 15000 | Wait through a redirect chain |
| `POST /api/wait-for-idle` | `quietPeriod` 500, `timeout` 10000 | Network quiet and no CSS animations |
| `POST /api/wait-for-navigation` | `timeout` 10000 | Next navigation event |
| `POST /api/force-navigate` | `url` (`about:blank`), `terminateScripts` (true) | Recover a frozen page (infinite loop). Works while busy |
| `POST /api/abort` | — | Cancel the running operation and free the server. Works while busy |

---

## Interaction

All take an element (see addressing) unless noted.

| Endpoint | Fields (defaults) | Notes |
|----------|-------------------|-------|
| `POST /api/click` | `button` (`left`/`right`/`middle`), `clickCount` (1; 2 = double), `timeout` (5000) | Waits for navigation on links. Returns `changes` (URL, title, errors) |
| `POST /api/click-at` | `x`, `y` (viewport CSS px, required), `button`, `clickCount` | Clicks whatever is painted there, including cross-origin iframes. No element |
| `POST /api/type` | `text` **or** `value` **or** `html`; `append` (false) | **Clears the field first.** `append: true` keeps existing text. `"text": ""` clears. Handles contenteditable. 400 if no content given. There is no `/api/fill` |
| `POST /api/select` | `value` | Selects a `<select>` option by value. Returns `actual` |
| `POST /api/key` | `key` (required), `modifiers` (`["Shift","Control","Alt","Meta"]`) | Element optional (default: focused). Keys: `Tab`, `Enter`, `Escape`, `Space`, `Backspace`, `Delete`, arrows, `F1`–`F12`, or a character |
| `POST /api/hover` | — | Real mouse move: triggers `:hover`, `mouseenter` |
| `POST /api/scroll` | `direction` (`down`/`up`/`top`/`bottom`), or `x`/`y` absolute; `scrollIntoView` (false) | Element optional (auto-detects the scroll container) |
| `POST /api/drag` | `from`, `to` (element objects) or `fromRef`/`toRef`/`fromSelector`/`toSelector`; `steps` (10); `html5` (auto) | Returns `path`: `html5`, `cdp`, or `cdp+html5` |
| `POST /api/upload` | `path` or `paths[]` (absolute host paths) or `base64` + `fileName`; `submit` (false) | Targets `<input type="file">`, hidden ones too. Blocked by `--safe` |
| `POST /api/find` | `text` (required), `regex`, `caseSensitive`, `highlight`, `scrollTo` (n), `visibleOnly` (true) | Matches with context, selector, rect. No element. `POST /api/find/clear` removes highlights |
| `POST /api/batch` | `actions: [{action, ...params}]` | Runs `click`, `type`, `select`, `text`, `attribute`, `hover`, `scroll`, `wait`, `sleep` in order in one call |

---

## Reading elements

| Endpoint | Fields | Returns |
|----------|--------|---------|
| `POST /api/text` | element | Inner text (pierces shadow DOM). Multi-mode: `targets`, `selectors`, `patterns` → `values` map |
| `POST /api/attribute` | element, `attribute` | HTML attribute value |
| `POST /api/property` | element, `property` | Live DOM property — use for `value`, `checked`, `selectedIndex`, `disabled` in React/Angular/Vue apps |
| `POST /api/extract` | `selector`, optional `fields`, `limit` | Repeating elements as a JSON array. `{"selector":"table.data"}` uses `<th>` as keys; `{"selector":".card","fields":{"name":"h3","url":"a@href"}}` maps fields (`@attr` reads an attribute, `.` is the container) |

---

## Waiting

| Endpoint | Fields (defaults) | Returns |
|----------|-------------------|---------|
| `POST /api/wait` | element, `timeout` (5000) | `found: true/false` — does **not** fail on timeout |
| `POST /api/wait-for-network` | `urlPattern` (substring, required), `method`, `status`, `timeout` (10000) | The matching request |
| `POST /api/wait-for-idle` | `quietPeriod` (500), `timeout` (10000) | When network and animations are quiet |

---

## Assertions

Results accumulate per session and appear in the journal. Every assertion accepts an optional `message` label. Read results with `GET /api/assertions` (gate-free): `passed`, `failed`, `total`, `allPassed`, `results[]`.

| Endpoint | Required fields | Passes when |
|----------|-----------------|-------------|
| `POST /api/assert/page-contains` | `text` | Page text contains it |
| `POST /api/assert/page-not-contains` | `text` | Page text does not contain it |
| `POST /api/assert/element-visible` | element | Element is visible |
| `POST /api/assert/element-not-visible` | element | Element is hidden or absent |
| `POST /api/assert/element-text` | element, `expected` | Inner text equals `expected` |
| `POST /api/assert/element-contains-text` | element, `expected` | Inner text contains `expected` |
| `POST /api/assert/element-attribute` | element, `attribute`, `expected` | Attribute equals `expected` |
| `POST /api/assert/element-count` | `selector`, `expected` (int) | Number of matches equals `expected` |
| `POST /api/assert/url` | `expected` | URL contains it (case-insensitive) |
| `POST /api/assert/title` | `expected` | Title contains it (case-insensitive) |
| `POST /api/assert/reset` | — | Clears all results |

---

## Dialogs

Native `alert` / `confirm` / `prompt` / `beforeunload`. Set the policy **before** the action that opens the dialog. Dialog routes are gate-free.

- `POST /api/dialog/handle` — `accept` (true = OK, false = Cancel), `promptText`.
- `GET /api/dialog` — last dialog: `type`, `message`, `defaultValue`.
- `POST /api/dialog/dismiss` — clear the last dialog record.

---

## Tabs

Each tab has its own console, network log, mocks, and refs. Reads and actions target the **active** tab.

- `GET /api/tabs` — `index`, `id`, `title`, `url`, `isActive`, `owner` (`human`/`agent`/`shared`).
- `POST /api/tabs/new` — optional `url`, `owner` (default `agent`). The new tab becomes active.
- `POST /api/tabs/switch` — `tabIndex` (0-based, required).
- `POST /api/tabs/close` — optional `tabIndex` (default active). The last tab cannot be closed.
- `GET /api/console`, `GET /api/network`, `GET /api/storage`, `POST /api/execute-js`, and `POST /api/fetch` accept `tabIndex` or `urlMatch` (URL substring) to target another tab without switching.

---

## Console, network, downloads

### GET /api/console (gate-free)
Messages with level `log`, `info`, `warning`, `error`. `POST /api/console/clear` empties it.

### GET /api/network (gate-free)
Captured traffic. Each entry has `id`, `method`, `url`, `statusCode`, resource type, `durationMs`, `servedFromCache`.

| Param | Effect |
|-------|--------|
| `errors=true` | Only 4xx/5xx (excludes Trowser's own probe traffic) |
| `url=<substring>` · `method=POST` · `status=404` · `statusRange=500-599` · `type=Fetch` | Filters |
| `includeBody=true` · `includeHeaders=true` | Add bodies (captured up to 100 KB) and full headers, including `Set-Cookie` |
| `last=N` (or `limit=N`) | Only the newest N matches |
| `summary=true` | One line per request (`#id METHOD status url`), best after heavy traffic |

- `GET /api/network/{id}` — one entry with headers and captured body.
- `POST /api/network/clear` — empty the log.
- `GET /api/network/har` — HAR 1.2 export; same filters, plus `includeBody=true` and `path=<file>` to write to disk.

### Downloads
- `GET /api/downloads` — `id`, `url`, `suggestedFileName`, `path`, `state`, `bytes`, `mime`.
- `POST /api/downloads/wait` — `fileNameContains`, `afterId`, `timeout` (30000). Resolves only when `completed` and the file exists; 400 if the download was interrupted.
- `POST /api/downloads/assert` — check filename, mime, `minBytes`, file exists, completed.

---

## HTTP from the browser

### POST /api/fetch
Sends a request with the page's cookies and session, like the app would. Relative URLs resolve against the current page. Blocked by `--safe`. Prefer this over `fetch()` inside `execute-js` (no CORS problems, structured result).

| Field | Default | Description |
|-------|---------|-------------|
| `url` | required | Absolute or relative |
| `method` | `GET` | Any verb, including `HEAD`, `OPTIONS`, `TRACE` |
| `headers` | — | Object |
| `json` | — | Serialized for you; sets `Content-Type: application/json` |
| `body` | — | Raw string (form-encoded, XML, ...). Wins over `json` |
| `bodyBase64` / `bodyFile` | — | Body as Base64 or from a local file — avoids PowerShell quote escaping |
| `redirect` | `follow` | `manual` returns the 3xx status and `Location` instead of following |
| `serverSide` | `false` | Send from .NET instead of the page: lets you set `Origin`, `Referer`, `Host`; still sends browser cookies unless `includeBrowserCookies: false` |
| `cookies` | — | One-shot `Cookie` header (does not change the jar). `""` = anonymous |
| `timeout` | `30000` | ms |

Returns `ok`, `status`, `statusText`, `redirected`, `url`, `headers`, `body`, `durationMs`, plus `identityUsed` and `cookiesSent` (names only) — check those before concluding a response was anonymous.

`POST /api/fetch/batch` — `requests: [ {same fields} ]`, `concurrent` (true), `includeBodies` (false; bodies truncated to `bodyMaxChars`, default 200).

`PUT /api/header-overrides` — `{"headers": [{"name": "X-Test", "value": "1", "enabled": true}]}` adds or replaces headers on all browser traffic; `GET` lists, `DELETE` clears. Blocked by `--safe`.

---

## Running code

### POST /api/execute-js
`{"script": "document.title"}` — the field is **`script`**, not `expression`. Multi-statement scripts are wrapped for you and the last expression is returned; use explicit `return` after a final `if`/`for`. Promises are awaited up to `timeout` (30000). Optional `frame`, `tabIndex`, `urlMatch`. Blocked by `--safe`. Do not download large assets or call other origins with `fetch()` here — it may hang until 504; use `/api/fetch`.

### POST /api/execute-script
Runs a C# script: `{"code": "..."}` (`script` is an alias). Same engine as `Trowser.exe --run test.csx`. Blocked by `--safe`. `GET /api/scripting-help?topic=overview` returns a cheat sheet (topics: `map`, `interaction`, `assert`, `wait`, `network`, `fetch`, `mock`, `security`, `template`, `all`); the full guide is `scripting-reference.md`.

### Recording
`POST /api/record/start` records the human's clicks and typing as a `.csx` script. `GET /api/record/status`. `POST /api/record/stop` — optional `description`, `toJournal` (true adds a replayable journal entry), `path` — returns `script`.

---

## Session state and environment

### Resetting
- `POST /api/clear-session` — clears console, network, assertions, mocks, intercepts, throttle, viewport, emulation, downloads, trace. **Keeps cookies and storage (stays logged in).** Prefer this.
- `POST /api/clear-all` — the same plus cookies, localStorage, sessionStorage. Optional `{"preserve": ["cookies", "storage"]}`.

### Cookies and storage
- `GET /api/cookies` (optional `?name=`).
- `GET /api/storage?type=local|session|indexeddb` (optional `key`; for IndexedDB `db`, `store`, `limit`).
- `POST /api/storage/set` — `key`, `value`, `type` (`local`). `POST /api/storage/delete` — `key`. `POST /api/storage/clear`. Writes are blocked by `--safe`.
- Cookie writes (`/api/cookies/set|delete|clear`) are in the full reference.

### Viewport, emulation, throttling
- `POST /api/viewport` — `preset` (`SmallPhone` 320×568, `BigPhone` 412×915, `LandscapePhone` 844×390, `SmallPad` 768×1024, `BigPad` 1024×1366, `BigDesktop` 1920×1080, `Desktop` = reset) **or** `width` + `height`. `GET` shows the current size.
- `POST /api/emulation` — any subset of `geolocation {latitude, longitude, accuracy}`, `locale` (`"sv-SE"`), `timezone` (`"Europe/Stockholm"`), `colorScheme` (`light`/`dark`/`no-preference`), `reducedMotion` (`reduce`), `userAgent`, `permissions {"geolocation": "granted"}`. `DELETE /api/emulation` clears.
- `POST /api/network/throttle` — `preset` (`Offline`, `2G`, `Slow3G`, `3G`, `4G`) or `downloadKbps` + `uploadKbps` + `latencyMs`. `DELETE` restores full speed.

### Action trace
`POST /api/trace/start` (`maxSteps` 200, `domSnapshots` false) → act → `POST /api/trace/stop` → `GET /api/trace` for a timeline of automation steps.

---

## Quality audits

All run on the current page and need no body unless noted.

| Endpoint | What it checks |
|----------|----------------|
| `POST /api/audit-all` (alias `/api/quicktest`) | Everything below plus cookie, storage, supply-chain, and misconfiguration checks, in one call. Each module reports independently; see `summary.allPassed`. Pass `includeApiInventory: false` for a quick pass (tens of seconds instead of minutes) |
| `POST /api/accessibility` | WCAG via axe-core. `level` (`A`/`AA`/`AAA`, default `AA`), `selector` |
| `POST /api/tab-order` | Real Tab / Shift+Tab walk: skipped elements, focus traps, positive `tabindex`, modal focus leaks. `selector`, `expectedOrder`, `maxSteps` (150) |
| `POST /api/performance` | Web Vitals (LCP, CLS, INP, TTFB, FCP), navigation timing, resource breakdown |
| `POST /api/validate-html` | HTML markup errors |
| `POST /api/seo` | Title, meta description, robots, canonical, Open Graph, hreflang, JSON-LD, h1 count |
| `POST /api/check-links` | Broken links and redirects. `scope` (`anchors`/`resources`/`all`), `external` (true), `concurrency` (10), `delayMs` (100) |
| `POST /api/compatibility` | JavaScript features unsupported on older iOS/Android |
| `POST /api/consistency` | Distinct fonts, sizes, colors, control heights; unoptimized images |
| `POST /api/third-party` | External scripts, styles, iframes, fonts; domains, sizes, SRI coverage |
| `POST /api/resource/snapshot` → act → `POST /api/resource/compare` | Memory and DOM-node growth across a flow (`rememberBaseline: true` then `useRememberedBaseline: true`) |

## Basic security (passive)

| Endpoint | What it checks |
|----------|----------------|
| `POST /api/security` | Passive overview: tech stack, vulnerable JS libraries, security headers, CORS, DOM XSS patterns, mixed content, cookies, source maps, storage, HTTP methods, common sensitive paths. `includeDiscover: false` skips the path wordlist |
| `POST /api/security/headers` | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server disclosure. `urls[]` to sweep several |
| `POST /api/security/js-libraries` | Known-CVE JavaScript libraries (Retire.js) |
| `POST /api/security/tech-stack` | Servers, frameworks, CDN, WAF, CMS, with evidence and confidence |

---

## Journal (findings and notes)

The journal is the session timeline: your actions and assertions are logged automatically; add notes and bugs yourself. All journal routes are gate-free.

### POST /api/journal

| Field | Applies to | Description |
|-------|-----------|-------------|
| `kind` | all | `note` (default), `observation`, `bug`, `enhancement`, `test-idea`, `charter`, `testing` |
| `note` | all | Title / text (aliases `text`, `title`). Extra lines become the body |
| `details` | all | Markdown body |
| `severity` | non-bug kinds | `info`, `low`, `medium`, `high`, `critical` |
| `evidence` | all | `observed`, `inferred`, `hypothesis`, `untested` |
| `tags` | all | String array |
| `steps`, `actual`, `expected`, `priority`, `oracle`, `notes` | bug, enhancement | `steps` is a string or array; `priority` is `low`–`critical` (use it instead of `severity`) |
| `screenshot` | all | Path from `GET /api/screenshot`; embedded in the HTML report |

```json
{ "kind": "bug", "note": "Search doesn't trim whitespace",
  "steps": ["Enter '  foo  ' in search", "Click Search"],
  "actual": "0 results", "expected": "Results for 'foo'",
  "priority": "high", "evidence": "observed", "tags": ["search"] }
```

- `GET /api/journal` — `since=<index>` (incremental), `last=N`, `type=bug`, `tag=`, `q=` (search), `view=index|full`. Response has `entries[]`, `total`, `revision`, `deleted[]`.
- `PATCH /api/journal` — `index` plus fields to change. `DELETE /api/journal?index=N`.
- `GET /api/journal/export?format=html|markdown|json` — the report; optional `path` writes it to disk.

### Talking to the human tester
- `POST /api/message` — `text`, `level` (`info`/`warning`/`error`), `duration` (8000 ms). Shows a banner in the Trowser window.
- `POST /api/decision` — ask the tester to choose: `question`, `options` (2–6), `recommendation`, `lane` (`steer` default: returns the default and keeps the question open; `gate`: blocks until answered; `review`: never blocks), `timeout` (300000). `GET /api/decision/{id}` picks up a later answer.

---

## Common mistakes

- Using a ref after the page changed. Re-read `/api/state` after navigation or any click that re-renders.
- Treating a navigate response as "page ready". Add `wait-for-idle` / `wait-for-final-navigation` on SPAs and SSO.
- Sending `text` as a locator to `/api/type`. It is the typed content; use `byText`.
- Calling `/api/fill`, `/api/press`, or passing `expression` to `execute-js`. Use `/api/type`, `/api/key`, and `script`.
- Using `clear-all` when you want to stay logged in. Use `clear-session`.
- Reading a clean page and stopping. Check `GET /api/console` and `GET /api/network?errors=true` — many failures never reach the screen.
- Fetching cross-origin URLs inside `execute-js`. Use `POST /api/fetch`.

---

## Everything else (see trowser-api-reference.md)

The full reference **[trowser-api-reference.md](trowser-api-reference.md)** also covers: network mocking and request interception (fault injection, breakpoints, replay), cookie writes, load testing, raw HTTP (`/api/fetch-raw`), batch scenarios (`/api/test-scenario`, `.trw` files), pointers and checkpoints, robustness testing (monkey test, fuzzing, interrupter), Web MCP page tools, client TLS certificates, and multi-instance peer and identity testing for authorization checks. It also documents more than 100 security scanners and probes (injection, XSS, SSRF, CSRF, IDOR/BOLA, JWT, OAuth/SAML, cache, smuggling, WebSocket, LLM red-teaming) and the OWASP-style orchestration playbooks, all of which take an explicit `safetyMode`. The method for using them is in `SecurityTestingWithTrowser.md`. For a one-line list of every endpoint and MCP tool, see [trowser-api-index.md](trowser-api-index.md).
