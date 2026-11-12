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
| Safe mode | `--safe` blocks JS execution, scripting, mocking, cookie/storage manipulation, `POST /api/fetch` (+ batch), `POST /api/upload`, `POST /api/fuzz`, `POST /api/storage` (write; same as `/storage/set`), `POST /api/intercept/replay`, `POST /api/load-test`, CSRF/methods/path-traversal/ssrf-scan/**open-redirect-scan** probes, `POST /api/security/verify` (+ batch), `POST /api/security/sqli-scan`, `POST /api/security/js-audit`, `POST /api/security/nuclei-scan`, `POST /api/security/jwt-analyze`, `POST /api/security/jwt-forge`, `POST /api/security/brute-force`, `POST /api/security/idor-scan`, `POST /api/security/mass-assignment-scan`, `POST /api/security/auto-scan`, `POST /api/security/swaggering`, `POST /api/security/secrets-harvest`, `POST /api/security/smuggling`, `POST /api/security/host-header`, `POST /api/security/waf-bypass`, `POST /api/security/chain-patterns` **add/remove only**, `POST /api/websocket/send`, `POST /api/websocket/close`, `POST /api/security/websocket-audit`, `POST /api/security/websocket-authz`, `POST /api/security/cswsh-test`, Law code operations (`POST /api/laws/validate|add|replace|delete|author|proposals/accept`), etc. **Allowed in safe mode:** `POST /api/security/chain-analyze`, `GET /api/security/chain-findings`, `GET /api/security/chain-patterns`, `POST /api/security/chain-patterns` with `action=list`, `GET /api/orchestrate/playbooks`, `POST /api/orchestrate/dry-run/*`, `POST /api/vpx/render`. Orchestration playbooks (`POST /api/orchestrate/*`) respect the `safetyMode` in the request body — `SecurityPreflight` enforces host-based restrictions and caps mode to `safe` when `--safe-probes-only` is active. |
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
{"ref": 3, "frame": "child"}
{"selector": "#in-frame", "frame": "iframe#child-frame"}
```

Ref numbers come from `GET /api/state` → `interactiveElements`. Hidden elements have `ref: -1`. After page changes, re-fetch `/api/state` for fresh refs. Pass `frame` (or use a frame-scoped snapshot) for iframe targets; **inspectable cross-origin** frames support ref-based `click`/`type` the same way as `execute-js`. Framed snapshots include `parentUrl`, `frameUrl`, `frameTitle`, and `refsActionable` (false when refs cannot be driven — see `interactionHint`).

**`byText` matching** is case-insensitive and whitespace-normalized (multiple spaces/tabs/newlines → single space). It also matches the **accessible name** (same as snapshot `label` / `role`+`name`), including **`input[type=submit|button|reset]` `value`**. MCP click/hover tools also accept `text` as an alias for `byText`. On **`POST /api/type`** / **`browser_type`**, `text` means **content to type** (not a locator) — use `byText` for a visible-text locator.

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
| `type` | Filter: `action`, `assertion`, `message`, `error`, `screenshot`, `script-output`, `recording`, `pointer`, `decision`, or a note kind (`note`, `bug`, `enhancement`, `observation`, `charter`, `testing`, `test-idea`, `user`). `type=bug` extracts only bug reports. |
| `source` | Filter: `api` (LLM/REST), `gui` (human tester), `system` (auto-generated) |
| `origin` | Filter by human-facing origin: `agent` (api), `user` (gui), `auto` (system) |
| `evidence` | Filter: `observed`, `inferred`, `hypothesis`, `untested` |
| `tag` | Filter by exact tag (case-insensitive) |
| `q` | Free-text search across summary, details, URL, tags, and field values (`search` is accepted as an alias) |
| `view` | `index` (titles-only) or `full`. When omitted and `total` > 40, defaults to `index`. |
| `indexes` | Comma-separated journal indexes — returns full entries for those ids only |

Response: `{ entries[], count, total, logging, revision, deleted[], view? }`. Each full entry: `{ index, timestamp, type, kind?, source, origin, summary, details?, severity?, evidence, fields?, tags?, url? }`. Index view omits `details` and `fields`. For `bug`/`enhancement` entries, `fields` contains `steps` (string or array), `actual`, `expected`, `priority`, `oracle`, `notes`. `revision` increments on add, update, and delete. `deleted` lists indices removed this process session (never reused). `type` also accepts `recording`.

**Efficient polling pattern:**
1. `GET /api/journal?since=0` → entries 1-3, remember `lastSeen=3`
2. `GET /api/journal?since=3` → only new entries (4, 5…)
3. Empty `entries[]` = no new activity. Also check `deleted` so you drop stale citations.

### POST /api/journal
Add a structured entry to the journal. Entries are classified by `kind` so bugs, enhancements, test ideas and charters can be extracted programmatically later. API actions and assertions are auto-logged; use this endpoint for everything else.

| Field | Required | Applies to | Description |
|-------|----------|------------|-------------|
| `kind` | | all | `note` (default), `user`, `charter`, `testing`, `test-idea`, `observation`, `bug`, `enhancement` |
| `note` | ✅* | all | Primary text / title (`text` and `title` are accepted aliases). *Optional when at least one structured field is given for a bug/enhancement. Multi-line values use the first line as title and the rest as markdown body. |
| `details` | | all | Optional markdown body (if omitted, extra lines of `note` become the body). |
| `severity` | | note, observation, charter, testing, test-idea, user | `info`, `low`, `medium`, `high`, `critical`. Not used for bug/enhancement — use `priority`. If sent on a bug/enhancement without `priority`, a compatible value (`low`/`medium`/`high`/`critical`) is stored as `priority`. |
| `evidence` | | all | Epistemic classification: `observed`, `inferred`, `hypothesis`, `untested`. LLM notes default to `inferred`; auto-logged actions default to `observed`; `test-idea` defaults to `untested`. |
| `tags` | | all | Array of strings for grouping/filtering (e.g. `["login", "security"]`). Normalized to lowercase. |
| `url` | | all | Page URL. Auto-captured from the browser if omitted. |
| `steps` | | bug, enhancement | Reproduction steps — a string or an array of strings (e.g. `["Open login", "Enter blank password", "Click submit"]`) |
| `actual` | | bug, enhancement | Actual observed behaviour |
| `expected` | | bug, enhancement | Expected behaviour |
| `priority` | | bug, enhancement | `low`, `medium`, `high`, `critical`. The rank for bugs and enhancements (replaces `severity` for these kinds). |
| `oracle` | | bug, enhancement | Why you believe this is a bug |
| `notes` | | bug, enhancement | Additional notes / workarounds |
| `screenshot` | | all | Path to a screenshot (e.g. from `GET /api/screenshot`). The Journal panel lists the path; HTML export embeds the image. |

Examples:
```json
{ "note": "Login page repaints twice" }
{ "kind": "charter", "note": "Stress the checkout flow", "tags": ["checkout", "stress-test"] }
{ "kind": "test-idea", "note": "Paste 10k-char input into search", "tags": ["search", "edge-case"] }
{ "kind": "bug", "note": "Search doesn't trim whitespace",
  "steps": ["Enter '  foo  ' in search", "Click search button"],
  "actual": "0 results", "expected": "Results for 'foo'",
  "priority": "high",
  "tags": ["search", "input-validation"],
  "screenshot": "C:\\...\\search-empty.png" }
```

Response includes all stored fields for verification: `{ index, timestamp, type, kind, source, summary, severity, fields, tags, url }`.

Bypasses the gate — always available, even when the server is busy.

### PATCH /api/journal
Update an existing journal entry. Body must include `index`. All other fields are optional and use the same vocabulary as POST (`kind`, `note`/`text`/`title`, `details`, `severity` for non-bug kinds, `tags`, `url`, structured bug fields including `priority`, `screenshot`). Omitted fields are left unchanged; send an empty string / empty array to clear. Editing a bug/enhancement drops leftover `severity` in favour of `priority`. **Gate-free**.

Response: the updated entry (same shape as POST). `404` if the index is unknown.

### DELETE /api/journal
Remove an entry. Query: `index` (required). The index is never reused; subsequent GET responses include it in `deleted[]`. **Gate-free**.

Response: `{ deleted, revision, total }`. `404` if the index is unknown.

### GET /api/session-memory
Volatile session memory for the built-in AI Assistant (focus, tasks, last compact handoff). **Gate-free**.

Response: `{ mission?, focus?, tasks[], handoff?, compactCount, lastCompactAt? }`.

### POST /api/session-memory
Update session memory. Body: `{ "action": "get"|"set_focus"|"add_task"|"update_task", ... }`. **Gate-free**.

| Action | Fields |
|--------|--------|
| `get` | (none) — returns current memory |
| `set_focus` | `focus` |
| `add_task` | `text`, optional `journalIndex` |
| `update_task` | `id`, optional `text`, `status` (`open`/`doing`/`done`/`dropped`), `journalIndex` |

### GET /api/journal/export
Render the full journal as a formatted report — HTML (REST default when `format` is omitted), Markdown, or a true JSON round-trip. Bugs/enhancements are grouped and priority-sorted. Screenshot files are **embedded** in HTML (base64) and referenced by path in Markdown. The docked Journal panel does not embed images. **Gate-free**.

| Query Param | Description |
|-------------|-------------|
| `format` | `html` (REST default), `markdown` / `md` (MCP `browser_journal_export` defaults to markdown), or `json` (JournalEntry + attached pointers for Open/Save) |
| `path` | Optional file path to also write the report to disk |
| `json` | If `true`, return `{ format, content, path? }` JSON instead of the raw document (for html/markdown). `format=json` already returns the bundle. |

The Journal panel header keeps **Report** and **Record**; **Open**, **Save**, and **Log Settings…** are in the ⋯ menu (and on right-click when not on an entry). Per-entry **Show me**, **Copy**, **Edit**, and **Delete** live on the right-click menu (Show me is greyed out when the entry has no URL, pointer, repro, or embedded recording script). Clicking an entry URL navigates the current tab. The panel search box uses `q` (all text), plus `type` / `source` filters. For `type=recording` entries with `fields.csx` (or a readable `fields.csxPath`), **Show me** navigates to the start URL and runs the script.

### POST /api/journal/import
Import a `trowser-journal` JSON bundle produced by `format=json` export (or the panel Save command). New indexes are assigned; pointer ids are remapped on collision. **Gate-free**.

```json
{ "path": "C:\\...\\journal.json" }
```

Or POST the bundle object itself (`format`, `version`, `entries`, `pointers`). MCP: `browser_journal_import`.

---

## Pointers & Checkpoints

A **pointer** is a symmetric "this, here, at this moment, and why" primitive: either a human (via the `!?` snip) or an agent (via `browser_point`) can create one. It renders as an on-screen overlay for the human and as JSON for the agent, is journalled as the handoff record (`type: "pointer"`, with the id in `fields.pointerId`), and always keeps a **frozen visual crop** so a reader still sees what was meant even when re-resolution fails. A **checkpoint** is a timestamp that bounds "what has happened since we last synced" — it records the current journal position so a handoff can send only what changed.

MCP tools: `browser_point`, `browser_pointers`, `browser_checkpoint`.

### POST /api/pointer
Create a pointer. Anchor it with a `ref` (preferred), `selector`, semantic locator fields (`role`+`name`, `testId`, `byText`, `label`, `placeholder`), and/or a `rect`. A frozen crop is captured automatically. Runs through the gate (touches the WebView for the crop).

| Field | Description |
|-------|-------------|
| `kind` | `element` (default), `region`, `range`, `absence` (something missing — use with `rect`), or `artifact` (non-page UI; carries a `source` label, no DOM anchor) |
| `caption` | Why you are pointing — what the human should notice |
| `author` | `agent` (default) or `human` |
| `ref` | Snapshot ref number (records the current `refGeneration`) |
| `selector` | CSS selector |
| `testId` / `role` / `name` / `label` / `byText` / `placeholder` | Semantic locator fields (a durable locator expression is derived in priority order) |
| `rect` | Bounding rect in CSS pixels: `{x, y, width, height, scrollX?, scrollY?}` |
| `checkpointId` | Attach to a specific checkpoint (defaults to the most recent) |
| `source` | For `artifact` pointers: where it came from (e.g. `"script console"`) |
| `url` | Page URL (auto-captured if omitted) |
| `crop` | Capture a frozen crop (default `true`) |

Returns the created pointer, including `id`, `status` (`resolved`/`stale`/`unresolvable`), `cropPath`, and `anchors`.

### GET /api/pointers
List pointers (in-memory, **gate-free**). Optional filters: `author`, `kind`, `status`, `tabId`, `checkpointId`. Returns `{ pointers, count, revision }`.

### GET /api/pointer/{id}
Fetch a single pointer by id. **Gate-free**.

### DELETE /api/pointer/{id}
Remove a pointer by id.

### POST /api/pointer/{id}/resolve
Re-resolve a pointer's anchor against the current DOM and update its status. Prefers the CSS selector, then the stored rect (via `elementsFromPoint`, adjusted for scroll drift). On failure the pointer becomes `unresolvable` — honest, so a reader falls back to the frozen crop instead of a confidently-wrong highlight. Returns `{ pointer, resolved, reason? }`.

### POST /api/checkpoint
Create a checkpoint bounding "now" (records the current journal index). Optional `label`, `url` (auto-captured). Returns the checkpoint (`id`, `label`, `journalIndex`, `url`, `createdAt`).

### GET /api/checkpoints
List checkpoints. **Gate-free**. Returns `{ checkpoints, count, latest }`.

### GET /api/checkpoint/{id}
Fetch a checkpoint with a summary of activity **since** it (GUI actions, errors, pointers). **Gate-free**.

---

## Decisions

A **decision** is the agent asking the human to make a call: a question, 2–6 options, and a recommendation. The tester answers with one click on an A/B/C/D card in the AI Assistant panel. Attention chrome (taskbar overlay + flash, AI Assistant badge, amber status bar) stays until the question is answered, defaulted, expired, or cancelled — not merely until the window is focused. Every answer — and every default that fired because nobody answered — is journalled (`type: "decision"`, with the id in `fields.decisionId` and `fields.decisionPhase` of `asked` or `resolved`), which is what makes the record accountable after the fact. All decision endpoints are in-memory and **gate-free**.

MCP tools: `browser_decide`, `browser_decisions`.

**Lanes** — chosen by whether the agent can proceed without an answer:

| Lane | Behaviour |
|------|-----------|
| `gate` | `POST /api/decision` **blocks** until the human answers or the timeout fires. Use only when the agent genuinely cannot continue |
| `steer` (default) | Returns the provisional default after an optional `graceMs` hold, and leaves the question open so a later human answer can redirect the run. The response carries `provisional: true` when still pending |
| `review` | Never blocks — a call put on the record for the human to weigh in on |

The card footer shows time remaining at discrete milestones only (5 min, 4, 3, 2, 1, 45 s, 30, 15) — not a ticking clock every second.

### POST /api/decision
Ask the human to make a call. Blocks only in the `gate` lane.

| Field | Description |
|-------|-------------|
| `question` | What needs deciding, in the tester's terms (**required**) |
| `options` | 2–6 answers, in order; keys `A`, `B`, `C`… are assigned automatically. With `allowOther`, at most **5** listed options (Other takes the next letter). Strings, or objects with `{label, detail}` (**required**) |
| `lane` | `gate`, `steer` (default), or `review` |
| `recommendation` | The option the agent recommends, by key (`"B"`) or label. Shown to the tester as the suggested answer |
| `default` | Option applied if nobody answers in time. In the `steer` lane it falls back to `recommendation`, then the first option |
| `allowOther` | When `true`, add a lettered **Other…** option (next key after your list, e.g. A,B,C → **D**). Answer with that key or REST alias `option: "other"`, `note: "<text>"` |
| `graceMs` | **Steer only:** hold the response up to this many ms, preferring a fast human answer before returning the provisional default (`0` = immediate; max `120000`) |
| `urgency` | `low`, `normal` (default), or `high`. High uses a red attention treatment; normal is amber. Flash resumes if the window is deactivated while the question is still open |
| `timeout` | How long the question stays open, in ms (default `300000` = 5 min; min `5000`, max `1800000`) |
| `pointerIds` | Pointer ids showing what the question is about — rendered on the card |
| `checkpointId` | Attach to a checkpoint (defaults to the most recent) |
| `url` | Page URL (auto-captured if omitted) |
| `wait` | `gate` only: set `false` to create the question and poll later instead of blocking (default `true`) |

Returns `{ decision, resolved, provisional, answer, guidance }`. `answer` is `{key, label, detail, by, note}` or `null`; `by` is `human`, `default`, or `agent`. For a custom Other answer, `key` is the assigned letter (e.g. `"D"`) and `label`/`note` carry the typed text. `guidance` is a one-line instruction for the agent covering what to do next.

### GET /api/decisions
List decisions. Optional filters: `status` (`pending`, `answered`, `defaulted`, `expired`, `cancelled`), `lane`. Returns `{ decisions, count, pending, revision }`.

### GET /api/decision/{id}
Fetch a single decision, wrapped the same way as `POST /api/decision`. This is how an agent picks up a `steer` answer after proceeding on the default, or a `gate` answer it chose not to wait for.

### POST /api/decision/{id}/answer
Record an answer. Fields: `option` (key or label, **required**), `note` (required for Other — the custom text; use the lettered key or alias `"other"`), `by` (defaults to `human`). Returns **409** if the decision is already resolved — the record cannot be rewritten after the fact — and **400** for an unknown option.

### DELETE /api/decision/{id}
Withdraw a pending question the agent no longer needs answered, so it stops asking for attention. Optional `reason` is journalled. Returns **409** if it is already resolved.

---

## Page State & Inspection

### GET /api/ping
Health check (no auth). Returns `busy`, `currentOperation` (method + path label only), and `note`. Does **not** include page URL, title, or query strings — use authenticated `GET /api/state` / `GET /api/info` for that.

Dialog routes (`GET /api/dialog`, `POST /api/dialog/handle`, `POST /api/dialog/dismiss`) bypass the operation gate so you can set dialog policy or read the last dialog while another call is in progress.

### POST /api/abort
Force-cancel the stuck operation and return server to idle. Bypasses the gate (works even when busy). Returns `aborted` (the cancelled operation), `message`, and optionally `gateForceReset: true` when the handler did not release the gate within 5s — the server clears `busy` and swaps in a fresh gate so new calls can proceed (the UI thread may still be stuck; use **`POST /api/force-navigate`**). Does not break a **frozen page** (infinite loop); use force-navigate or MCP **`browser_force_navigate`** for CDP recovery.

**Cancellation guarantees:** Abort sets `OperationCancellation` on the active gated request. Scanners that check the token **between probes** (SQLi, XSS, open-redirect, SSRF, auto-scan pipeline steps, attack-surface enrichment, API inventory auth-delta probes) stop at the next checkpoint and release the busy gate when the gated handler finishes. In-flight single HTTP fetches are **not** hard-killed mid-socket. **`POST /api/audit-all`** returns **`partial: true`** with modules completed before cancel (later modules show `skipped: true`); it does not return HTTP 499 mid-body. **`POST /api/security/auto-scan`** and budgeted scanners return **`partial: true`** / **`budgetExhausted: true`** with findings collected so far.

### POST /api/force-navigate
Recover a **frozen** page: CDP **`Runtime.terminateExecution`** + **`Page.navigate`** (optional `terminateScripts`, default `true`). Body: `{ "url": "about:blank", "terminateScripts": true }`. **Bypasses the gate**; cancels stuck gated op after success. Response may include `gateForceReset: true` (same semantics as **`POST /api/abort`**). Same navigation-scope rules as `/api/navigate` except `about:` always allowed.

### GET /api/info
Server version, current URL/title, **`navigationScope`** / **`navigationRestricted`**, **`externalMcpMode`** (`core` / `security`; `full` is an alias of security), assertion/console/network counts.

### GET /api/state
**Main endpoint.** Full page snapshot: **URL**, title, `pageText` (3000 chars default), `headings`, `interactiveElements` (with ref numbers, plus `checked` for radio/checkbox), `imageSummary`, `consoleErrors`, `networkErrors`, `assertionSummary`. The `url` field is always included — no extra call to `/api/info` needed.

When configured, also includes **Shadows** fields: `securityShadow` (Shadow — passive audits summary when active), `powerMode` (Trowser Power mode — enabled/showOverlays), and `redTeamWhisper` (clues — enabled/notifyGui/lastHints/clues/newClues). Same toggles as **Settings → Experimental**.

**`securityPreflight`** — when the network log has traffic but no meaningful interaction requests (XHR/fetch, form POST navigations, or other state-changing calls with bodies), reports `navigationOnly: true` with a recommendation to log in, submit forms, search, add to cart, or run `POST /api/security/crawl-light` before attack-surface / auto-scan.

| Param | Description |
|-------|-------------|
| `?fullText=true` | Return untruncated pageText |
| `?visible=false` | Include hidden elements (those with `ref: -1`). Default: visible only. |
| `?selector=<css>` | Scope pageText and interactiveElements to elements within matching container(s) |
| `?frame=<id\|name\|css>` | Collect interactive refs inside an iframe (`frameId` from `frames[]`, iframe `name`, or CSS selector). **Inspectable cross-origin** frames (`inspectable: true`) use the WebView2 frame handle for snapshot **and** ref-based actions (`click`, `type`, …). Response adds `parentUrl`, `frameUrl`, `frameTitle`, `refsActionable`, and `interactionHint` when actions are not available. |
| `?tag=<name>` | Filter elements by tag (`input`, `button`, `a`, `select`, etc.) |
| `?type=<name>` | Filter elements by type/role (`text`, `checkbox`, `submit`, etc.) |
| `?q=<text>` | Filter elements by text/label search (case-insensitive) |
| `?limit=<n>` | Max number of interactiveElements |
| `?sections=<list>` | Comma-separated sections to include (e.g., `interactiveElements,url,title,frames`). Also: `securityShadow`, `powerMode`, `redTeamWhisper`. `refGeneration` always included. |

Snapshot includes `frames[]`: `{ frameId, name, url, sameOrigin, parentFrameId }`. Interactive elements include `frameId` when scanned inside a frame. Frame-scoped snapshots set `viewport` to the **frame** layout size (`coordinateSpace`: `frame`) and add `parentViewport` (`coordinateSpace`: `top`). Filtering does not change ref numbering -- refs remain valid for actions.

### GET /api/frames
Thin list of iframes (same shape as `frames[]` on `/api/state`). No gate.

### POST /api/state/enrich
Batch-fetch text/attributes for multiple refs in one call.

| Field | Required | Description |
|-------|----------|-------------|
| `refs` | Yes | Array of ref numbers |
| `fields` | Yes | Array of field names (`text`, `accessibleName`, `label`, `href`, `value`, `checked`, `placeholder`, `disabled`, `tag`, `id`, `className`, `name`, `type`, `role`, `title`, `required`, `readOnly`, `maxLength`, `pattern`, `min`, `max`, `step`, `src`, `alt`, `target`, `action`, `method`, `tabIndex`, `contentEditable`, `data-testid`, etc.). For form controls, `text` falls back to the accessible name (associated `<label>`, `aria-label`, etc.) when the control has no inner text. |

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
Browser console messages. Levels: `log`, `info`, `warning`, `error`. **Gate-free** — safe for passive polling. Optional **`?tabIndex=`** or **`?urlMatch=`** reads another tab without switching (restores the prior active tab afterward). Response includes `queriedTab` and `activeTab`.

### POST /api/console/clear
Clear captured console messages. Empty body or `{}`.

### GET /api/network
Network traffic log with optional filters. **Gate-free** — safe for passive polling. Each entry includes `durationMs` (response time in milliseconds, measured from request start to response received) and `servedFromCache` (true when Chromium served it from disk, memory, prefetch, or a service worker).

| Param | Description |
|-------|-------------|
| `?errors=true` | Only 4xx/5xx; **excludes** Trowser scanner/header-probe traffic (`isTrowserGenerated: true`) unless `?includeSynthetic=true` |
| `?url=<substring>` | Filter by URL (case-insensitive) |
| `?method=<GET\|POST\|...>` | Filter by method |
| `?status=<code>` | Filter by exact status |
| `?statusRange=<min>-<max>` | Filter by inclusive status range (e.g. `500-599`). If set, `status` is ignored |
| `?type=<Script\|Fetch\|...>` | Filter by resource type |
| `?includeBody=true` | Include request/response bodies |
| `?includeHeaders=true` | Include full HTTP headers (including `Set-Cookie` captured via CDP) |
| `?includeDataUrls=true` | Include `data:` URLs (default **false** — base64 images blow agent context) |
| `?preferInteractive=false` | Disable soft Document/Fetch/XHR-first ordering (default prefers interactive types) |
| `?maxUrlChars=500` | Truncate displayed URL length (default 500) |
| `?limit=N` / `?last=N` | Return only the **most recent** N matching entries (MCP `browser_network` parity). Response includes `shown` and `truncated` (list paging only — not response body completeness) |
| `?summary=true` | Compact one-line-per-request for **all** matches (`summary: string[]`, each line starts with `#id`) instead of `entries` — best after heavy traffic |
| `?id=<entryId>` | Single log entry by auto-increment `id`. Prefer `GET /api/network/{id}` when you want headers and the captured body in one call |
| `?responseBodyOffset=` / `?responseBodyLimit=` | With `includeBody=true`, return a slice of the **in-memory** captured response (full resource may require `POST /api/fetch` when `responseBodyTruncated` is true) |
| `?tabIndex=` / `?urlMatch=` | Read another tab's log without switching (restores prior active tab). `GET /api/tabs` lists `networkEntryCount` per tab. |

Document POST navigations missing from WebView2 are **backfilled from CDP** (`responseSource: "cdp-backfill"`, optional `cdpFrameId`). **`fetch` redirect chains** (e.g. login POST → 302) may add a **`cdp-redirect-hop`** row with `redirectedToUrl` when WebView2 only shows the final response. When WebView2 already logged the hop but dropped the body or a custom request header, the same CDP data is merged onto that row (Cookie is not copied back). Each entry includes body capture metadata: `responseBodyCapturedChars`, `contentLengthBytes` (from `Content-Length` when present), `responseBodyTruncated` (capture **cap** only), `responseBodySizeMismatch` (declared size vs captured, with tolerance), `bodyCaptureLimitChars` (102400), `requestBodyTruncated`. `responseBodyNote` is set when a text-like response (document, fetch, script, stylesheet) has no captured body. Summary lines start with `#id` and use `respTruncCap` for cap hits and `respLenMismatch` for large declared/captured gaps — not for 1–2 byte encoding differences. The list response includes `entryLookup` describing the per-id route.

### GET /api/network/{id}
One captured entry. **Gate-free.** Headers and any captured body are included unless `?includeHeaders=false` or `?includeBody=false`. `?responseBodyOffset` / `?responseBodyLimit` slice the in-memory body. `?maxUrlChars=0` (the default here) leaves the URL intact. Unknown ids return 404.

`responseBodyCapturedChars: null` means this log row never stored a body. `POST /api/fetch` performs a new request; it is not the original capture. Entries expose **`statusCode`**. `?summary=true` on the list returns `count`, `errors`, and `summary` and omits `entries`.

### POST /api/network/clear
Clear captured network entries. Empty body or `{}`. Call after reviewing network data to free memory.

### GET /api/network/har
Export the in-memory network log as **HAR 1.2** JSON. Filters mirror `/api/network`. Optional **`?tabIndex=`** / **`?urlMatch=`** target another tab. Optional `?path=` writes the HAR to a host file and returns a confirmation.

| Param | Description |
|-------|-------------|
| `?includeHeaders=false` | Omit headers (default include) |
| `?includeBody=true` / `?includeBodies=true` | Include captured bodies (default false) |
| `?url=` `?method=` `?errors=true` `?page=true` | Same filters as `/api/network` |
| `?path=<file>` | Write HAR to this path instead of returning JSON |

### GET /api/downloads
List captured downloads: `id`, `url`, `suggestedFileName`, `path`, `state`, `bytes`, `totalBytes`, `mime`.

### POST /api/downloads/wait
Wait until a matching download reaches **`completed`** and the result file exists on disk (when a path was assigned). Does **not** resolve on `inprogress`. Interrupted/cancelled downloads return HTTP 400.

| Field | Description |
|-------|-------------|
| `fileNameContains` | Optional filename substring |
| `timeout` | ms (default 30000) |
| `afterId` | Only match downloads with id greater than this |

### POST /api/downloads/assert
Assert filename / mime / minBytes / file exists / completed state on a captured download.

### POST /api/downloads/clear
Clear the download log. `{ "deleteFiles": true }` also deletes saved files.

### POST /api/clear-all
Reset all test session state in one call. Clears: console log, network log, cookies, mock rules, intercept rules, assertion counters, network throttle, viewport override, **emulation**, **download log**, **action trace**, localStorage, and sessionStorage.

Optional body: `{ "preserve": ["cookies", "storage"] }` — categories to keep intact. Accepted values: `cookies`, `storage`, `mocks`, `intercepts`, `throttle`, `viewport`, `emulation`, `downloads`, `trace`.

### POST /api/clear-session
Lighter reset — clears test artifacts (console, network, assertions, mocks, intercepts, throttle, viewport, emulation, downloads, trace) but **preserves cookies and web storage**. Use when you need a clean test slate without destroying the user's session.

### GET /api/assertions
Current assertion results: `passed`, `failed`, `total`, `allPassed`, `results[]`. **Gate-free** — safe for passive polling.

---


## Inspiration

### GET /api/inspiration
Get a random testing inspiration message — a creative prompt, heuristic, or lateral-thinking trigger to spark new test ideas. Use it to get inspired, but don't necessarily follow it unless it resonates. **Gate-free**. Response: `{ "message": "..." }`.

---

## Scripting help

### GET /api/scripting-help
Curated C# scripting (`.csx`) cheat sheet for LLMs and agents writing repeatable scripts. Prefer this over inventing MCP tool-call JSON as a “script”. **Gate-free**.

| Query | Default | Description |
|-------|---------|-------------|
| `topic` | `overview` | Section: `overview`, `map` (MCP/REST→C#), `interaction`, `assert`, `wait`, `network`, `fetch`, `mock`, `security`, `template`, `topics`, or `all` |

Response: `{ "topic": "overview", "text": "...", "topics": ["assert", "fetch", ...] }`.

**MCP equivalent:** `browser_scripting_help` with optional `topic`. Full reference: `trowserkit/scripting-reference.md`.

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

## Coverage

### GET /api/coverage

Reflective coverage lens from the session journal: pages visited, interactive elements exercised, and which quality characteristics have been touched. Awareness of gaps, not a coverage target. **Gate-free.**

**MCP:** `browser_coverage`.

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

Response **`url`** (and `/api/state` → `url`) uses a consistent **`UriFormat.UriEscaped`** form of the current address (query/fragment percent-encoding is uniform for programmatic diffs).

**Completion milestone:** A successful navigate response means the **navigation event finished** and Trowser read **`url`** / **`title`** from the active WebView tab — not necessarily that SSO/OAuth/SAML redirects have settled, lazy chunks have loaded, or an SPA router has rendered the final view. After federated login or hash-router apps, chain **`POST /api/wait-for-final-navigation`** (redirect chains; `quietPeriod` after last navigation) and/or **`POST /api/wait-for-idle`** (network quiet + no CSS animations), then **`GET /api/state`** before snapshots, client-surface, or trace-input. For stuck event loops, use **`POST /api/force-navigate`**.

| Field | Required | Description |
|-------|----------|-------------|
| `url` | For URL nav | Target address; prepends `https://` if no scheme (never pass `"back"` as URL — use `action`) |
| `action` | For history | `back` or `forward` |
| `reload` | No | When `true` and the URL matches the current address, **reload** the document (browser refresh — may **re-submit** a prior form POST). Default same-URL navigate uses CDP **`Page.navigate`** for a **fresh GET** (`navigationKind`: `fresh-get`). |
| `ignoreCertificateErrors` | No | Accept invalid TLS for this navigation |

**Response (URL navigate):** `navigationKind` is `navigate`, `fresh-get`, or `reload`. When `reload` may re-POST a form, `reloadWarning` explains the risk. For **`fresh-get`**, `documentReloaded` is `true` when navigation timing shows the document was replaced, `false` when the same URL was a browser no-op (no 30s timeout — the call returns promptly).

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
Click an element. Auto-waits for visible + enabled. Auto-waits for navigation on `<a href>` links. Returns `changes` (URL, title, errors) if page changed. When the resolved `href` does not match the URL the SPA actually routes to (placeholder root link + `pushState` to a detail route), the wait succeeds once the tab moves to a new same-origin URL — not only when the address equals `href`.

| Field | Default | Description |
|-------|---------|-------------|
| element | *(required)* | `ref`, `selector`, or locator |
| `frame` | — | Same-origin iframe: `frameId`, iframe `name`, or CSS selector of `<iframe>` |
| `button` | `"left"` | `left`, `right`, `middle` |
| `clickCount` | 1 | 1=single, 2=double-click |
| `timeout` | 5000 | Auto-wait (ms) |

**Cross-origin iframes:** `frame` / snapshot scoping uses the parent document’s same-origin `contentDocument` — not a security gate, but the browser’s DOM boundary. Cross-origin frames still appear in `frames[]` (`sameOrigin: false`, often `inspectable: true` for `execute-js` with `frame`). For **clickjacking** PoCs (overlay + click under a decoy), use **`POST /api/click-at`** or **`POST /api/security/clickjack-test`** rather than refs inside the embedded document.

### POST /api/click-at
CDP **`Input.dispatchMouseEvent`** at viewport **x/y** (CSS pixels from the page top-left). Clicks whatever is **painted** at that point, including **cross-origin iframe** content, without DOM or ref access inside the frame. Prefer **`POST /api/click`** when same-origin refs exist (faster, navigational-link handling).

| Field | Required | Description |
|-------|----------|-------------|
| `x`, `y` | Yes | Viewport coordinates (CSS px) |
| `button` | No (`left`) | `left`, `right`, `middle` |
| `clickCount` | No (`1`) | Single or multi-click |

**MCP:** `browser_click_at`.

### POST /api/drag
Drag from one element to another. By default: HTML5 DragEvent path when the source is `draggable`, otherwise CDP mouse (`mouseMoved` → `mousePressed` → stepped `mouseMoved` → `mouseReleased`). Only one path runs (no double-fire) unless you explicitly need both.

| Field | Required | Description |
|-------|----------|-------------|
| `from` | Yes* | Nested element object (`ref`/`selector`/locator) |
| `to` | Yes* | Nested element object |
| `fromRef` / `fromSelector` | * | Flat alternatives to `from` |
| `toRef` / `toSelector` | * | Flat alternatives to `to` |
| `steps` | No (default 10) | Intermediate CDP move steps |
| `html5` | No | `true` = HTML5 only; `false` = CDP only; omit = auto |
| `frame` | No | Optional same-origin iframe scope for both ends |
| `timeout` | No | Auto-wait (ms) |

Response includes `path`: `"html5"`, `"cdp"`, or `"cdp+html5"`.

### POST /api/type
Clear input and type text (or append with `append: true` / `clearFirst: false`). Auto-waits for visible + enabled. Automatically detects **contenteditable** elements (rich text editors) and uses `execCommand('insertText')` for compatibility. Pass `html` to insert formatted HTML.

> **There is no `/api/fill`.** Use `/api/type` (clears first by default). To append without clearing: `"append": true` or `"clearFirst": false`. For one character at a time after a clear, call `/api/type` once then `/api/key` / `browser_press_key` per character.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator (`byText`, `label`, …). Alone, `value` still means the `@value:` locator |
| `text` | One of text/value/html | Text to type. Explicit `""` clears the field |
| `value` | One of text/value/html | **Alias for typed content** when the element is already addressed by `ref`/`selector`/another locator (MCP-shaped `{ref, value}`). Without another locator, `value` remains the `@value:` element locator |
| `html` | One of text/value/html | HTML content for contenteditable elements (uses `insertHTML`) |
| `append` | No (default `false`) | If `true`, append to existing content instead of clearing |
| `clearFirst` | No (default `true`) | If `false`, append to existing content instead of clearing |

Returns HTTP 400 if none of `text`, content-`value`, or `html` is provided (no silent success with an empty type).

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
| `x` / `y` | — | Absolute `scrollTo` position (CSS pixels). `scrollX` / `scrollY` are aliases. When set, `direction` is ignored. |
| `scrollIntoView` | false | Scroll element into viewport center |
| `timeout` | 10000 | Timeout in ms. Prevents hang if page is unresponsive |
| element | *(none)* | Omit to auto-detect scrollable container (or the window when `x`/`y` are set) |

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
Inner text of element. **Pierces shadow DOM.** Also supports **multi-extract**: pass `targets`, `selectors`, and/or `patterns` (label slices or named regex groups) — response `values` includes every key with `null` on failure.

| Field | Required | Description |
|-------|----------|-------------|
| element | Yes | `ref`, `selector`, or locator (single-element mode) |

### POST /api/extract-text
Alias for **multi-extract** on `POST /api/text` (`targets` / `selectors` / `patterns` only).

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

Single expressions (e.g. `document.title`, `1 + 2`) are evaluated directly. Multi-statement scripts are auto-wrapped in an IIFE and the **last expression is auto-returned** — e.g. `const x = 1; x + 1` returns `"2"` without needing an explicit `return`. Explicit `return` is still supported and is required when the final statement is a control-flow block (if/for/while). Leading comments are stripped automatically.

**Promises:** If the evaluated script returns a **Promise** (including `async` IIFEs and `.then()` chains), the host **awaits** it up to `timeout` ms and returns the settled value. Use `return await …` inside multi-statement scripts when you need the resolved value as the last expression. Unsupported syntax or compile errors surface as **500** with an error string — fix the script rather than assuming silent `undefined`. Top-level `await` is only valid when the wrapped script is async-compatible; prefer `return (async () => { … })()` when in doubt.

Do **not** `fetch()` JS bundles, source maps, or other large static assets inside execute-js — in-page downloads often hang until the timeout. Use **`POST /api/fetch`** with `"serverSide": true`, or **`POST /api/security/js-audit`** / **`secrets-harvest`**.

**Cross-origin HTTP:** In-page `fetch()` to another origin (e.g. a token endpoint on an IdP host) is usually **blocked by CORS** — the Promise may never settle and you get a **504** timeout. Prefer **`POST /api/fetch`** (browser cookie jar, no CORS) or **`serverSide`: true**. Timeouts may mention CORS when the browser console logged a blocked request.

| Field | Required | Description |
|-------|----------|-------------|
| `script` | Yes | JavaScript source to run. **Field name is `script` (not `expression`).** Multi-statement auto-wrapped with last-expression auto-return. |
| `frame` | No | `frameId` or `name` from `frames[]` / `GET /api/frames` — runs in that document (including **inspectable cross-origin** frames). Same IIFE auto-wrap as the main frame. |
| `timeout` | No (`30000`) | Max wait for Promise resolution in ms. Host-side; an in-page `AbortController` does not help if WebView2 never settles. |
| `tabIndex` | No | Run against this tab (0-based); active tab is restored after the call. |
| `urlMatch` | No | Run against the first tab whose URL contains this substring (alternative to `tabIndex`). |

**REST/JSON footgun (client-side prototype pollution):** Three layers behave differently:

| Layer | `__proto__` behavior |
|-------|----------------------|
| REST request JSON (host deserializer) | Often **does not** create an own `__proto__` key on a plain object — many .NET/JSON stacks treat `__proto__` specially when binding the body. |
| JavaScript **`JSON.parse('{"__proto__":{"x":1}}')`** in the page | Creates an **own** property named `__proto__` on the parsed object (`hasOwnProperty('__proto__') === true`). |
| JavaScript **object literal** `{ __proto__: { x: 1 } }` | Sets **prototype**, not an own key — different from `JSON.parse`. |

Pollution impact depends on a **later unsafe merge/assign** (e.g. `Object.assign(target, parsed)`), not on the parse step alone. For in-page probes, put the payload in the **`script` string** (or build objects inside JS). For REST-only tests of server-side PP, use the scanner endpoints — do not assume the execute-js request body shape mirrors `JSON.parse` semantics.

### POST /api/execute-script
Run C# test script (same engine as CLI mode). Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `code` | Yes* | C# script source. Canonical field name. |
| `script` | Yes* | Alias for `code` (accepted for DX compatibility). |

\* Provide **`code`** or **`script`**.

### POST /api/record/start
Start interaction recording to a temp `.csx`. Captures **human DOM** actions (clicks, typing via the page), not MCP/REST tool calls. Returns status `{ recording, startUrl, startedAt, actionCount }`. **409** if already recording. Not blocked by `--safe`.

### GET /api/record/status
Current recording state: `{ recording, startUrl, startedAt, actionCount }`.

### POST /api/record/stop
Stop recording and return the script. No Script Console / AI chat destinations — the response is the handoff for agents.

| Field | Required | Description |
|-------|----------|-------------|
| `description` | No | Label for journal summary and `// Description:` header |
| `toJournal` | No (`false`) | When true, add a journal `recording` entry with embedded `fields.csx` (Show me can replay) |
| `path` | No | Absolute `.csx` path to write (alias: `toFile`). Uses `ExportPathGuard`; **blocked in `--safe`** |

Response: `{ recording: false, script, narration, startUrl, actionCount, journalIndex?, filePath? }`.

MCP: `browser_record_start`, `browser_record_status`, `browser_record_stop` (Core pack).

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
Get storage entries. `?type=local|session|indexeddb` (default: `local`), `?key=<name>` for single value.

For **`type=indexeddb`**: returns `{ origin, method, truncated, databaseCount, recordCount, databases[] }` with per-store records (values truncated). Optional `?db=`, `?store=`, `?limit=` filters. Prefer this over page scripts for secrets/JWT/storage audits.

### POST /api/storage
**Alias of [`POST /api/storage/set`](#post-apistorageset).** Set key/value. **Required:** `key`, `value`. **Optional:** `type` (default: `"local"`). Blocked in safe mode. Use this path if you expect symmetric CRUD-style URLs; behavior is identical to `/api/storage/set`. IndexedDB write via set is not supported.

### POST /api/storage/set
Set key/value. **Required:** `key`, `value`. **Optional:** `type` (default: `"local"`). Blocked in safe mode.

### POST /api/storage/delete
Delete key. **Required:** `key`. **Optional:** `type`. Blocked in safe mode.

For **`type=indexeddb`**: pass `database` (or `key`) to delete a database, or `database` + `store` to clear one object store.

### POST /api/storage/clear
Clear all entries. **Optional:** `type`. Blocked in safe mode. For IndexedDB, optional `database`/`db` filter deletes matching databases.

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

Related but separate: **network throttle** (`/api/network/throttle`) and **environment emulation** (`/api/emulation`).

---

## Environment Emulation

CDP overrides for geolocation, locale, timezone, `prefers-color-scheme` / `prefers-reduced-motion`, user-agent, and (when supported) permissions. Cleared by `/api/clear-session` and `/api/clear-all`.

**Cross-origin note:** After each successful navigation, Trowser re-applies the stored geolocation override and re-grants `permissions` for the **new origin** (CDP permissions are origin-scoped). `GET /api/emulation` reflects the intended session overrides; you do not need to re-`POST` after navigate.

### GET /api/emulation
Current overrides.

### POST /api/emulation
Set any subset:

```json
{
  "geolocation": { "latitude": 59.33, "longitude": 18.07, "accuracy": 10 },
  "locale": "sv-SE",
  "timezone": "Europe/Stockholm",
  "colorScheme": "dark",
  "reducedMotion": "reduce",
  "userAgent": "Custom UA",
  "permissions": { "geolocation": "granted" }
}
```

Clear a single geo override with `"geolocation": { "clear": true }` or `"geolocation": null`. Empty string for `locale` / `timezone` / `userAgent` clears that field.

**Locale surface:** `locale` sets CDP `Emulation.setLocaleOverride`, `navigator.language` / `navigator.languages`, `Accept-Language` on requests (q-value-free list for Chromium), and default **`Intl.DateTimeFormat` / `Intl.NumberFormat`** when called with no locale argument. Host OS locale may still affect APIs that read the system directly.

### DELETE /api/emulation
Clear all emulation overrides.

---

## Action Trace

Ring-buffer timeline of automation steps (not a Playwright `.zip` Trace Viewer). Optional compact DOM snapshot ids (off by default).

### POST /api/trace/start
`{ "domSnapshots": false, "maxSteps": 200 }`

### POST /api/trace/stop

### GET /api/trace
### GET /api/trace/export
JSON: `{ tracing, domSnapshots, steps: [{ t, action, args, url, refGeneration, domSnapshotId, ... }], domSnapshotData?: { [id]: html } }`.
When started with `domSnapshots: true`, steps may include `domSnapshotId` and `domSnapshotData` holds compact outerHTML snippets.

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

Each tab has isolated console, network, mocks, and refs. **Gated reads and actions** (`GET /api/state`, `/api/interactive`, click/type/navigate, most security scans) target the **currently active tab** unless a call accepts **`tabIndex`** (e.g. `POST /api/diff-state`).

### GET /api/tabs
List all tabs (`index`, `id`, `title`, `url`, `isActive`, `owner`). `owner` is `human`, `agent`, or `shared`. May include `tabOwnershipWarning` when the last agent action targeted a human-owned tab. Poll this when a human and an agent share a session — refs and network logs are per tab.

### POST /api/tabs/new
Open new tab (becomes active). **Optional:** `url`, `owner` (`human` | `agent` | `shared`). REST/MCP default to `agent` so automation does not hijack the tester's page.

### Agent tab ownership (automation)
By default (**`agentTabPolicy`: `stayOnActive`** in `%APPDATA%\\Trowser\\api-user.json`), REST/MCP mutations run on the **currently active tab** — the usual **human login → agent handoff** flow. Set **`agentTabPolicy`** to **`preferDedicatedAgentTab`** to restore the older behavior: the first **`POST /api/navigate`**, **`POST /api/click`**, **`POST /api/type`**, etc. **opens or switches to an agent-owned tab** so automation does not clobber the tester page.

Subsequent gated calls target whichever tab is **active** until **`POST /api/tabs/switch`**. Pin work explicitly with `POST /api/tabs/new` and `"owner": "agent"`. Many responses include top-level **`activeTab`** (`tabIndex`, `tabId`, `url`, `title`, `owner`).

**Tab targeting without switching:** optional **`tabIndex`** or **`urlMatch`** (substring of tab URL) on **`GET /api/storage`**, **`POST /api/execute-js`**, and **`POST /api/fetch`** — the call runs against that tab and restores the previous active tab afterward. Supplying either field also skips automatic agent-tab selection on mutation endpoints.

### POST /api/tabs/close
Close tab. **Optional:** `tabIndex` (default: active tab). Cannot close last tab.

### POST /api/tabs/switch
Switch active tab. **Required:** `tabIndex` (0-based). All following state reads and actions use this tab until the next switch.

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
Remove rule. **Required:** `urlPattern`. **Optional:** `method` — when set, only rules with that HTTP method are removed; when omitted, all rules matching `urlPattern` are removed.

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
Send an HTTP request from the browser context using `fetch()`. Includes the page's cookies, auth tokens, and session state automatically. Relative URLs resolve against the current page origin. Blocked in safe mode. These calls are recorded as application traffic (visible to attack-surface and costly-operations). Scanner and fuzzer replay stays excluded. `serverSide: true` does not appear in the browser network log.

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
| `includeBrowserCookies` | No | `true` | When the request runs server-side (`serverSide: true`, TRACE/CONNECT, or identity override below), merge the WebView cookie jar before applying `Cookie` / `identityOverride`. Set `false` to send only caller-supplied cookies/headers. The default stays `true` because server-side fetch is how logged-in probes bypass forbidden headers. Every result includes `identityUsed` and `cookiesSent` (names only) so a 200 is not mistaken for anonymous access. |
| `cookies` | No | — | One-shot `Cookie` header for this request only (does **not** mutate the browser jar). Implies server-side transport and defaults `includeBrowserCookies` to `false` unless you set it explicitly. An empty string (`"cookies": ""`) or an empty `Cookie` header sends **no** cookies (anonymous server-side), unless `includeBrowserCookies` is explicitly `true`. Mutually exclusive with `identityOverride`. |
| `identityOverride` | No | — | `{ "peer": "<registered name>" }` or `{ "identity": "<captured name>" }` — replay that identity's cookies on the driver via server-side fetch without swapping the local session. Mutually exclusive with `cookies`. Response includes `identitySource`. |

Use `body` for raw string payloads (form-encoded, XML, etc.). Use `json` as a shorthand for JSON — it serializes the value and sets `Content-Type: application/json` when you did not already supply a `Content-Type` header (any casing). You do not need to set `Content-Type` manually when using `json`. Header names in `headers` are merged case-insensitively. Precedence: `body` → `bodyBase64` → `bodyFile` → `json`.

**PowerShell body escaping:** Single-quoted JSON strings in PowerShell cannot contain unescaped `'`, which makes SQL injection payloads like `' OR 1=1--` painful to pass via `body`. Three alternatives that avoid the issue entirely:
- **`bodyBase64`** — encode the payload to Base64 first: `$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("' OR 1=1--"))`, then `"bodyBase64": "$b64"`.
- **`bodyFile`** — write the payload to a temp file and pass the path: `Set-Content -Path payload.txt -Value "' OR 1=1--" -NoNewline`, then `"bodyFile": "C:\\path\\to\\payload.txt"`. No escaping needed.
- **Object pipeline** — build the request as a PowerShell object and let `ConvertTo-Json` handle escaping: `$obj | ConvertTo-Json -Compress | Invoke-RestMethod -Method Post ...`.

**`serverSide` mode:** Set `"serverSide": true` to route the request through .NET `HttpClient` instead of the browser's `fetch()` API. This allows overriding [forbidden headers](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name) like `Referer`, `Origin`, and `Host` that JavaScript cannot set. The browser's cookies (including HttpOnly) are still attached unless `includeBrowserCookies` is `false`. Use this when testing referrer-based restrictions, origin checks, or other header-sensitive server behavior. Not subject to CORS policies.

**Identity on the wire:** In-page `fetch` always uses the page jar (`identityUsed: "browser-page"`). Server-side results set `identityUsed` to `browser-session`, `browser-session+caller-cookies`, `caller-cookies`, `anonymous`, `peer:<name>`, or `identity:<name>`. `cookiesSent` lists cookie **names** only. Read these before concluding that a response was anonymous.

**Empty Content-Type:** A missing `Content-Type` still gets a default (`text/plain`, or `application/json` when `json` is set). An explicit empty value (`"Content-Type": ""`) sends the body with **no** Content-Type header, for parser paths that treat a missing type differently. It does not error.

**TRACE/CONNECT support:** These methods are blocked by browser `fetch()`. When used, Trowser automatically falls back to a server-side HttpClient request. The response includes `"type": "server-side"` and a `note` explaining this.

### POST /api/fetch-raw
Send HTTP/1.x bytes on a new TCP/TLS connection (not `HttpClient`, not WebView2). Use this when you need `Transfer-Encoding`, a custom `Content-Length`, duplicate header names, or a nonstandard request-line version token (`HTTP/1.0`, `HTTP/1.2`, …). Session header overrides are **not** applied. Blocked in `--safe`. TLS ALPN is pinned to `http/1.1`.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | Yes | — | Connect / SNI target (absolute `http` or `https`) |
| `requestLine` | No | `METHOD {path} HTTP/1.1` | Full request line, including the version token |
| `method` | No | `"GET"` | Used only when `requestLine` is omitted |
| `headers` | No | — | **Raw header block string** (not a JSON object) so duplicates survive |
| `body` | No | — | Body as UTF-8; `Content-Length` is not recomputed |
| `timeout` | No | `15000` | Timeout (ms) |
| `normalizeHeaders` | No | `true` | Convert header newlines to CRLF. Body is never rewritten. |

Response: `requestSent`, `status`, `statusText`, `headers` (string array), `body` (decoded when the response uses `Transfer-Encoding: chunked`), `bodyRaw` (wire body after headers, only when chunked), `bodyWasChunked`, `timedOut`, `hostWasAdded`, `durationMs`, `error`, `type: "raw"`. If the header block has no `Host` line, one is added from the URL authority.

Automated smuggling still uses `POST /api/security/smuggling`. Use `/api/fetch-raw` for a single crafted request (put a second request in `body` if you need pipelining).

### GET /api/header-overrides
List session header overrides. These apply only to **WebView2** traffic (browsing, in-page `fetch`, Send Browser). They do not apply to Send Direct, `/api/fetch-direct`, `/api/fetch-raw`, or security scanners.

### PUT /api/header-overrides
Replace the override list: `{ "headers": [{ "name": "User-Agent", "value": "…", "enabled": true }] }`. For each enabled row, the header is replaced if present or added if missing. A `User-Agent` override also updates `navigator.userAgent`. Blocked in `--safe`.

### DELETE /api/header-overrides
Clear all session header overrides. Blocked in `--safe`.

**Cross-origin redirect handling:** When `redirect: "manual"` is used and the target returns a cross-origin 3xx redirect, browser `fetch()` produces an opaque redirect (status 0, no headers). Trowser automatically detects this and re-issues the request server-side with `AllowAutoRedirect = false`, returning the actual 3xx status code, `Location` header, and response body. The response `type` will be `"manual-server-side"` to indicate the fallback.

Returns: `ok`, `status`, `statusText`, `redirected` (bool), `type` (`"basic"`, `"cors"`, `"manual-server-side"` for cross-origin manual redirects, `"server-side"` for TRACE/CONNECT), `url` (final URL), `headers`, `body`, `durationMs` (HTTP round-trip in milliseconds, measured from request start to body received — excludes `delayMs` and API gate wait). Not TTFB; for wire-level timing use `GET /api/network`.

### POST /api/fetch/batch
Multiple fetch calls in the browser context (or server-side when an item sets `serverSide`, `cookies`, or `identityOverride`). Recorded as application traffic, same as `/api/fetch`. **Body:** `requests` (array of objects with the same fields as `/api/fetch`: `url`, `method`, `headers`, `body` or `bodyBase64` or `bodyFile` or `json`, `redirect`, `timeout`, `cookies`, `identityOverride`, `includeBrowserCookies`, `serverSide`), `concurrent` (default `true`).

| Field | Default | Description |
|-------|---------|-------------|
| `includeBodies` | `false` | When true, each result includes a truncated `body` string (required for IDOR content evidence) |
| `includeBody` | — | Alias for `includeBodies` |
| `bodyMaxChars` | `200` | Max chars of response body when bodies are included (`0` = full body) |
| `maxBodyChars` | — | Alias for `bodyMaxChars` |
| `includeTiming` | `true` | Include `durationMs` per result |

Without `includeBodies`, results still include `bodyLen` but `body` is `null`. Use for authenticated race-condition tests (parallel polls, etc.). Blocked in safe mode.

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
| `apiInventoryMaxSeconds` | Wall-clock cap for API inventory enrichment inside audit-all (OpenAPI/JS/dev-artifact probes). On expiry returns `apiInventory.partial: true`, `timedOut: true` — not a full inventory. | `90` |
| `includeAuthDeltaProbes` | Session-only endpoint probes inside apiInventory | `false` (needs `safetyMode: "active"`) |
| `includeClickjack` | Clickjacking sweep (passive; active when `includeClickjackActive` + `safetyMode: "active"`) | `false` |
| `includeClickjackSweep` | Sweep sensitive URLs in clickjack pass | `true` |
| `includeClickjackActive` | Active iframe proof in clickjack pass | `false` (needs `safetyMode: "active"`) |
| `includeAiIntegration` | LLM surface discovery + passive AI-traffic signals | `true` |
| `includeActiveLlmRedteam` | Run llm-redteam-scan subset in aiIntegration block | `false` (needs `safetyMode: "active"`) |
| `llmRedteamMaxProbes` | Cap probes when active LLM red-team in audit-all | `8` |
| `safetyMode` | `"active"` enables secrets harvest (JS bundles, source maps) and BAC active probes. (`confirmBackend: true` accepted as legacy alias) | `"safe"` |
| `maxBytesPerFile` | Secrets harvest JS read cap | `524288` |

**Response `data`:** `elapsedMs`, **`partial`** (true when aborted mid-run or a module cancelled), optional **`cancelNote`**, **`moduleTimings`** (per-module `elapsedMs`; API inventory may show `timedOut` via `apiInventory.timedOut`), `summary` (`allPassed`, per-audit booleans including … **`insecureDesignClean`**, **`authenticationFailuresClean`**, **`apiInventoryClean`**, **`clickjackClean`**), then … **`insecureDesign`**, **`authenticationFailures`**, **`apiInventory`**, **`clickjack`**.

**Duration warning:** With **`includeApiInventory: true`**, audit-all runs attack-surface enrichment (HTTP OpenAPI probes, JS bundle hints). On busy sessions this can take **minutes** unless capped — use **`apiInventoryMaxSeconds`**, tighten **`maxProbeOrigins`** / **`maxJsScripts`**, or set **`includeApiInventory: false`** for a quick pass (~tens of seconds).

**`data.authenticationFailures`** — passive session-id grade, reset-token entropy, cookie flags, cached auto-scan auth categories, OAuth/SAML shadow counts; with `safetyMode: "active"` and `includeActiveAuthenticationProbe: true` runs sqli-login-sweep + default-credential-canary + captcha-replay micro-scans:

| Key | Description |
|-----|-------------|
| `isClean` | No auth-related cached/shadow/passive/active findings |
| `cachedAutoScanFindings` | `{ sqliLoginSweep, defaultCredentials, sessionFixation, passwordResetWeak, accountEnumeration, logoutInvalidation, jwtAcceptanceSweep, authBypassPivot, nosql, ldap, total }` |
| `shadowFindings` | `{ oauthOidc, saml, total }` |
| `passiveSignals` | `{ sessionIdEntropyGrade, resetTokenFindingCount, sessionCookieFlagGaps }` |
| `activeAuthenticationProbe` | `{ sqliLoginSweep, defaultCredentialCanary, captchaReplay }` when active |
| `issueCount` | Total across all sources |

**`data.insecureDesign`** — cached auto-scan + Shadow counts for race/captcha/workflow-skip; with `safetyMode: "active"` and `includeActiveInsecureDesignProbe: true` runs micro-scans:

| Key | Description |
|-----|-------------|
| `isClean` | No race, captcha-replay, or workflow-skip findings |
| `cachedAutoScanFindings` | `{ raceCondition, brokenAntiAutomation, workflowStepSkip, total }` |
| `shadowFindings` | Same shape from Shadow |
| `activeInsecureDesignProbe` | `{ raceCondition, captchaReplay, workflowSkip }` finding counts when active |
| `issueCount` | Total across cache + shadow + active |

**`data.security`** groups three scans (each matches the corresponding single endpoint’s `data`):

| Key | Same as |
|-----|---------|
| `isClean` | `true` only if CVE, XSS, mixed-content, and source-maps are all clean |
| `cve` | `POST /api/security/js-libraries` |
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
| `risk` | `none`, `low`, `high` (elevated only for ambiguous response framing) |
| `indicators` | Framing issues only (TE+CL, conflicting Content-Length) |
| `context` | Proxy/CDN/HTTP-version notes — not findings |
| `proxyDetected` | Whether Via/X-Forwarded-For / server product suggest a reverse proxy |
| `recommendation` | Next step (run active scan once per origin; act only on confirmed differential 404) |

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

**Response highlights:** `focusContextKind`, `focusContextLabel`, `scopeAutoDetected`, `backwardChecked`, `shiftTabConsistencyChecked`, `backwardCycleComplete` / `shiftTabConsistent` (null when backward walk was not performed), `forwardSteps` (with `inScope`), `issues[]`, `summary`.

**MCP:** `browser_tab_order`

### POST /api/performance
Web Vitals: LCP, CLS, INP, TTFB, FCP + navigation timing + resource breakdown. No params needed.

### POST /api/resource/snapshot
Point-in-time resource usage via CDP (after GC prep): JS heap, DOM nodes, documents, frames, event listeners, open WebSockets, optional live `HTMLElement` count. Passive — does not mutate the page. Each CDP call honors **`POST /api/abort`** and times out after 30s per call (HTTP **504**), releasing the API gate.

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
Passive **security overview** on the current page — same module set as the embedded quicktest **1 Security Scan**: tech stack, Retire.js CVEs, HTTP security headers, CORS (document URL), DOM XSS patterns, mixed content, cookies, source maps, web storage, HTTP methods on the document URL, and path discovery.

| Field | Default | Description |
|-------|---------|-------------|
| `includeDiscover` | `true` | Run `POST /api/security/discover` (wordlist scan) |
| `includeMethods` | `true` | Run `POST /api/security/methods` on the document URL |
| `wordlist`, `basePath`, `delayMs`, `spaMode` | discover defaults | Passed through when `includeDiscover` is true |
| `urls` | — | Optional multi-URL header sweep (same as `POST /api/security/headers`) |

**Response:** `isClean`, `elapsedMs`, and nested objects `techStack`, `jsLibraries`, `headers`, `cors`, `xss`, `mixedContent`, `cookies`, `sourceMaps`, `storage`, `methods`, `discover` (each matches the corresponding single-endpoint `data` shape). Top-level `isClean` is `false` if any included module reports issues.

**MCP:** `browser_security`

### POST /api/security/js-libraries
JavaScript CVE scan (Retire.js). No params needed. Detects libraries via `func` (live-DOM, including Bootstrap 3/4/5 plugin APIs), `uri`, `filename`, and `filecontent` (fetched script bodies — banners and characteristic tokens inside minified bundles). Response includes `caveats[]` and `hasBundledScripts` when few large bundled JS files are present; a clean result in that case is incomplete coverage, not proof. For declared dependencies, source maps, and OSV, use `POST /api/security/supply-chain-scan`.

**MCP:** `browser_security_js_libraries`

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

### POST /api/security/headers
HTTP security header analysis (OWASP). No params needed for the document URL. Checks CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server disclosure, deprecated headers, duplicate security headers, and HTTP TRACE method (XST risk). Pass `urls[]` to sweep multiple URLs (same behavior as before).

**MCP:** `browser_security_headers`

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
| `budget.maxSeconds` | `0` (none) | Stop sweep early with `budgetExhausted: true` and partial endpoint coverage |

**Response also includes:** `urlsSwept`, `sweepResults[]` (per-endpoint summary), `endpoints[]`. **Typical runtime:** document-only ≈ 15s; multi-endpoint sweep on WAN targets can run **many minutes** (origins × methods × URLs) — use `maxUrls` and `budget.maxSeconds` for agent-driven calls.

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
Fail-open probe: strip session cookies and invalid JWT on traffic-derived sensitive endpoints. **Requires `safetyMode: "active"`.** Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | network discovery | Optional explicit URLs |
| `maxEndpoints` | `10` | Max endpoints |
| `includeUnauthenticated` | `true` | Cookie-stripped replay |
| `includeInvalidToken` | `true` | Invalid Bearer JWT |
| `includeAfterError` | `true` | **Deprecated no-op** (simulated post-500 branch removed); accepted for compatibility |
| `skipStaticAssets` | `true` | Skip CSS/JS/images and common static URL patterns |
| `skipAuthSurfaces` | `true` | Skip login/register/oauth paths for unauthenticated checks |
| `skipPublicEndpoints` | `true` | Skip catalog/UX paths (search, languages, homepage) and non-sensitive GETs without Authorization in traffic |
| `registerChainFindings` | `true` | Feed `chain-analyze` |

Categories: `fail-open-unauthenticated`, `fail-open-invalid-token`.

**MCP:** `browser_security_fail_open_scan`

### POST /api/security/auth-control-identifier
Identify which cookies, headers, and token fields **actually gate** a captured request. Replays your captured template (headers/body from `endpoints[]` or the network log); when the template omits `Cookie` but the jar has session cookies for the host, the probe merges them and may return `session-cookie-not-in-baseline` with `inconclusive: true` if no candidates were testable. For each candidate runs **omit** and **one-character tamper** (middle alphanumeric — edge flips are too weak for padding/truncated compares) leave-one-out probes. Compares status + normalized JSON body to classify each identifier.

**Verdicts:**

| Verdict | Meaning |
|---------|---------|
| `enforced` | Omit and tamper both change the response — value is validated |
| `presence-only` | Omit changes response; tamper does not — existence check only |
| `ignored` | Neither omit nor tamper changes the response — sent but not validated |
| `value-checked-but-optional` | Tamper changes response; omit does not (rare) |
| `inconclusive` | Baseline was not HTTP 2xx |

For **enforced cookies**, the results include `cookieFlagWarning` (and a ⚠ in the GUI) when the jar/network flags lack **HttpOnly**, **Secure**, or **SameSite ≥ Lax**.

Candidates: **every cookie** (individually); headers matching auth/token/csrf patterns (or all headers when `allHeaders: true`); matching body/query fields (`__RequestVerificationToken`, `csrf`, `access_token`, etc.).

**Requires `safetyMode: "active"`.** Blocked in safe mode. Prefer the **Endpoint Probe** dialog for request selection; also available from the HTTP Request Editor (**Identify auth controls…**).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `endpoints` | network log | Array of `{ url, method?, headers?, body? }` |
| `url` / `method` / `headers` / `body` | — | Single-request shorthand when `endpoints` omitted |
| `allHeaders` | `false` | Test every non-hop-by-hop header, not only auth/token-like names |
| `includeBodyFields` | `true` | Include matching JSON/form body fields |
| `includeQueryFields` | `true` | Include matching query parameters |
| `maxEndpoints` | `5` | When falling back to network log discovery |
| `timeoutMs` | `12000` | Per-request timeout |

**Response:** `candidates[]` (per-identifier verdict + omit/tamper status), `rows[]` (flat mutation table), `consistency[]` (same name across multiple endpoints), `summary[]`.

**MCP:** `browser_security_auth_control_identifier`

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
| `spaMode` | `true` | Probes a random invalid path and excludes responses that match that baseline (same status, title, similar body length; 3xx also compare `Location` fingerprint). **Any response with API-shaped `Content-Type`** (`json`, `xml`, `text/plain`, etc.) is **never** removed — JSON APIs behind the same reverse proxy stay in `discovered` even when status/length align with the probe. Set `false` to keep HTML shell duplicates. A normal site whose unknown paths return **404** has no baseline, so this filter changes nothing |
| `baselineFilter` | `true` | Alias for `spaMode`. Omitted does not override an explicit `spaMode: false` (and the reverse) |
| `spaProbePath` | _(auto)_ | Optional custom probe path for SPA fingerprinting |

**Uniform auth redirects:** An invalid-path baseline is always probed. Paths that return the same 3xx status and the same redirect target fingerprint (`scheme://host/path`, query stripped) are filtered automatically — this suppresses Shibboleth/SAML/OIDC login-gate noise where every unknown path 302s to the IdP with unique `SAMLRequest`/`state` params. Playbooks also treat bare 3xx discoveries as `info` (not findings).

**Response** includes `spaMode` (effective value), `probeCount`, `spaFilteredCount`, `authRedirectFilteredCount`, `baselineNote` when shell duplicates were excluded or when kept rows still look like the baseline, `apiEchoCount` when API-shaped bodies match the baseline exactly, and when `discoveredCount === 0`: `zeroResultReason`. `baselineNote` is the hint that identical HTML 200s were the SPA index or a soft-404, including when `spaMode` was turned off and those rows were left in `discovered`.

### POST /api/security/crawl-light
Light same-origin crawler (BFS): follows `<a href>` links and enumerates `<form action>` URLs (GET navigation only — no POST submissions). Populates the network log before scanners. Not a full Monkey Trowser pass. Respects **`host`** when set (playbook orchestrators pass **`scope.host`** automatically).

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
CSRF assessment from the **live page** and **network log**. (1) Scans **GET forms** on the current page for state-changing fields (password, change/save/delete, etc.) without anti-CSRF hidden inputs (`get-form-no-csrf-token`, medium) or with tokens (`get-form-csrf-spec-violation`, low). (2) Successful state-changing requests (**POST/PUT/PATCH/DELETE**) with no CSRF token — **deduped by method + path + request shape** (form field names / JSON property names) so two different forms posting to the same URL (e.g. one with a token, one without) are analyzed separately. A header whose name contains `csrf` / `xsrf` / `forgery` (including a fixed flag such as `X-CSRF: 1`) is a token: the scanner replays **without** that header and does **not** substitute a fake secret when the captured value is not token-like. Other custom `X-*` headers that a simple cross-site form cannot set (not tracing or proxy headers) are stripped and the same request is replayed once. A **401/403** or a body that says the CSRF check failed becomes `custom-header-enforced` (`vulnerable: false`). A **2xx** after the strip stays `no-csrf-token`. (3) Passive **GET** traffic with mutation-like query/path (`get-request-no-csrf-token` / `get-request-csrf-spec-violation`). (4) For secret token-bearing endpoints, replays **missing** and **invalid** tokens. **`includeGet`: `true`** adds active missing/invalid tests for GET requests that already carry CSRF tokens. Browse and submit forms/API calls for network-based POST findings. A hidden field whose name is a CSRF token (including `csrf`) is **not** reported as `tokenLocation: "none observed"`. The scanner replays that form with the field removed and with an invalid value (`missing-token` / `invalid-token`). A 2xx/3xx without a CSRF rejection is "token present but not enforced". `tokenLocation: "none observed in form"` means the form was read and had no token field. Multipart bodies are scanned for `name="…"` token fields.

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
| `includeCrossSiteProof` | `false` | Browser-faithful cross-site CSRF from mocked `evil.trowser.test` (iframe POST, top-level POST, `fetch` with credentials) — same pattern as XS-Leaks/postMessage active probes |
| `maxCrossSiteProbes` | `3` | Cap when `includeCrossSiteProof` is true |
| `attackerSite` | `cross-site` | `cross-site` → `https://evil.trowser.test`; `same-site` → sibling host mock for SameSite experiments |

**Response:** `endpointsTested`, `unprotectedCount`, `vulnerableCount`, `customHeaderProbesRun`, `sameSiteContext` (`crossSiteCookieRisk`, `summary`, `sessionCookies[]`), `message`, `includeGet`, `stateChangingGetHints[]` (`url`, `reason` — informational GETs that may warrant `includeGet`; hints use path/query **tokens**, not raw substrings, and skip common static file extensions such as `.jpg`), `scenarios[]` (`url`, `path`, `endpoint` alias of `url`, `method`, `testType`, `tokenLocation` — `none observed` when no token; cross-site proofs use `testType` prefix `cross-site-`), optional `crossSiteProof` (`runId`, `attackerOrigin`, `proofs[]`, `credentialDelivery`, `browserModel`).

### POST /api/security/path-traversal
**Query mode (default, `mode` omitted or `query`):** Probes **GET** URLs (same origin as the current page) from the **network log** — or an explicit `urls` list — replacing path-like **query** parameters with traversal payloads. Default parameter names include `file`, `path`, `page`, `doc`, `include`, `template`, `view`, `content`, `folder`, `dir`, `load`, `read`, `resource`, `url`, `src`, `img`, and similar.

**Path mode (`mode`: `path` or `path-append`):** Appends each payload to the **URL path** after `basePath` or each entry in `pathBases` (for vulnerabilities in the path, not the query — e.g. `/app/../../../etc/passwd`). Fetches a baseline per base path, then compares disclosure heuristics. Findings use `paramName`: `(path-append)`.

Compares responses to **baseline** fetches and flags bodies that look like **`/etc/passwd`**, **`/etc/hostname`**, **`/proc/self/environ`**, **`/proc/self/cmdline`**, **`win.ini`**, or an error that echoes a resolved absolute path still containing `..` (for example `ENOENT … '/usr/src/app/../..'`).

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
Dedicated **HTTP open redirect** scanner (CWE-601): off-site **`Location`** on **3xx** responses (plus allowlist-prefix / null-byte bypass families). It does **not** confirm **client-side** redirects where JavaScript assigns `location.href` / `window.open` with no server redirect — use **`client-surface`** + **`trace-input`** (navigation-shaped payloads; see trace-input `sinks.classification: dom-open-redirect`).

Discovers **redirect-like parameters** (`redirect`, `url`, `next`, `return_to`, `continue`, etc.) from the **network log**, explicit `urls`, or **`endpointHints`** when attack surface lists params but captured URLs have no query string (e.g. DVWA `low.php` with `redirect` in links only).

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

**Response:** `message`, `candidatesProbed`, `payloadsSent`, optional `warnings[]` (caller-supplied urls/hints that were not probed), `observations[]` (non-vulnerability signals). **Discovery-only** runs (no `urls` / `endpointHints`) append a **`coverage`** observation and extend `message` with an explicit note: a clean result applies only to redirect-like parameters **already visible** in the session DOM/network log (not proof that an unvisited flow is safe). `findings[]` (`title`, `category`, `severity`, `confidence`, `endpoint`/`url`, `method`, `paramName`, `payload`, `statusCode`, `baselineStatusCode`, `location`, `indicator`, `evidence`/`snippet`, `bypassTechnique`, `source`).

**Priority:** `urls` / `endpointHints` / DOM-discovered redirect links outrank scaffold paths. If a hinted URL was not probed, `warnings` lists it — do not treat a scaffold-only run as coverage of that hint. Reproduce with `verbose: true` and/or a full `request` template (`?redirect=§redir§`).

**Indicators:** `external-location-redirect`, `protocol-relative`, `substring-filter-bypass`, `allowlist-prefix-bypass`, `allowlist-filter-bypass`, `null-byte-whitelist-bypass`, `dangerous-scheme-redirect`, `ssrf-via-open-redirect`.

**MCP:** `browser_security_open_redirect_scan`.

### POST /api/security/cache-map
Cache **identification + key-mapping indication**. Unique `?trowser_cb=` busters only — does **not** poison the live URL. `safetyMode: "safe"` runs identify + query/path mapping. `safetyMode: "active"` also probes a small curated header set and a fat GET (still on the busted URL). Logged-in cookies by default. Live-key error storage is **`cache-pollution-scan`**, not this endpoint.

**Safety gate:** Requires `"safetyMode": "safe"` or higher. Header/fat-GET mode needs `"active"` and is skipped under CLI `--safe`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `safe` | `safe` = identify + query/path mapping; `active` = also header + fat GET |
| `urls` | current page + cacheable assets | Target URL(s); `maxTargets` default `2` |
| `includeBrowserCookies` | `true` | Attach session cookies (logged-in mapping) |
| `headers` | built-in set | Restrict active header probes to these names |
| `maxTargets` | `2` | Max URLs |
| `timeout` | `15000` | Per-request timeout (ms) |

**Response:** `identify` (same shape as tech-stack `cache`), `oracle`, `keyComponents`, `comparisons[]`, `findings[]` (`unkeyed-reflected`, `unkeyed-cached`/`unkeyed-query`, `normalization-discrepancy`, `cacheable-error`, `key-explosion-possible`), `nextActions`. A cache existing is **not** a finding.

**MCP:** `browser_security_cache_map`.

### POST /api/security/cache-pollution-scan
**Live-key error pollution** (first dig-deep once a cache is identified). No query string is added. Phase 1 finds a header that forces a miss on the **clean** URL without splitting the key. Phase 2 combines that header with error-inducing unkeyed gadgets. Phase 3 is a fully clean GET. Confirmed `cache-error-stored` means other users may receive the stored error. **Not** in auto-scan. A14 runs it after cache-identify/map when `active` (skipped if no cache is in play).

**Safety gate:** Requires `"safetyMode": "active"`. **Blocked in `--safe`.** Response `warnings` remind that a confirmed hit stores an error on the shared URL.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` |
| `urls` | current page | Live URL (query string from the page is kept; no `trowser_cb`) |
| `includeBrowserCookies` | `false` | Public-cache attack unless `Vary: Cookie` |
| `cacheReplayDelayMs` | `300` | Delay before the clean confirm |
| `timeout` | `15000` | Per-request timeout (ms) |

**Response:** `bypassHeader`, `phase1[]`, `phase2[]`, `phase3`, `findings[]` (category `cache-poison`), `nextActions` (typically `cache-poison-scan` with the same bypass header).

**MCP:** `browser_security_cache_pollution_scan`.

### POST /api/security/cache-deception-scan
**Web Cache Deception (WCD)** scanner. Probes delimiter path variants (`/api/me/.css`, `;.css`, encoded `/` and `;`) with **authenticated** then **anonymous** GET (`SecurityProbeHttp` — session cookies vs none). Flags when response bodies are byte-equal (cached authed body served to anonymous client). Includes `Cache-Control` / `Age` / `X-Cache` evidence.

Always includes the **current page path**. Extra PortSwigger-style variants (`/wcd.css`, `?.css`, `%00.css`). Tentative matches (missing cache headers) are confirmed with a second anonymous GET.

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
Classic **web cache poisoning** scanner. Injects canary values via unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-Scheme`, `X-Amz-Website-Redirect-Location`, …), then replays a **fully clean GET** of the same URL. Prefer `bypassHeader` from **cache-pollution-scan** Phase 1 so the canary hits the **live** key. `useQueryBuster: true` is opt-in and maps a private slot (weaker proof). Skips `no-store` targets. Distinguishes `reflected-not-cached` vs `cached-persistence`.

**Safety gate:** Requires `"safetyMode": "active"`. Uses backend `HttpClient` (not browser `fetch` — arbitrary headers).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `urls` | current page | Target URL(s) |
| `headers` | built-in set | Unkeyed headers to probe (pass cache-map header candidates) |
| `canaryHost` | `cache-poison-probe.trowser.test` | Canary host marker |
| `bypassHeader` | — | Miss-forcing header name from pollution Phase 1 |
| `bypassHeaderValue` | `no-cache` / `1` | Value for `bypassHeader` |
| `useQueryBuster` | `false` | Opt-in `?trowser_cb=` private slot |
| `includeBrowserCookies` | `false` | Attach session cookies |
| `includeHeaderInjectionFuzz` | `false` | Fuzz with `header-injection` payload set (noisy; opt-in) |
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
HTTP Request Smuggling via raw TCP: confirmed = repeated differential 404 (CL.TE/TE.CL canary); everything else is informational. Timing stalls, TE obfuscation, duplicate Content-Length, and HEADER hygiene are notes, not bugs. Also fingerprints infrastructure (proxy/CDN, HTTP version, ALPN).

**Safety gate:** Requires `"safetyMode": "active"` — sends specially crafted HTTP requests with ambiguous CL/TE headers. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` — confirm that probes will be sent to the target. (`confirmBackend: true` accepted as legacy alias) |
| `url` | current page | URL to test |
| `techniques` | `["all"]` | `all`, `CL-TE`, `TE-CL`, `TE-TE`, `CL-CL`, `HEADER` |
| `timeoutMs` | `10000` | Per-probe timeout (ms, max 30000). Longer timeouts improve CL-TE/TE-CL detection reliability. |
| `delayThresholdMs` | `3000` | Timing differential (ms) used for informational stalls (min: 1000) |
| `teObfuscations` | `true` | Test Transfer-Encoding header mutations (recorded as notes, not confirmed desync) |

**Response:** `verdict` (`confirmed` \| `unconfirmed-architecture` \| `clean`) first, then `url`, `elapsedMs`, `summary`, `probesRun`, `findingCount`, `confirmedCount`, `findings[]` (`technique`, `severity`, `confidence`, `findingCategory`, `exploitable`, `confirmationMethod` — e.g. `differential-response`, `timing-only-incomplete-chunk` — `probeDetails`), `headerNormalization`, `infrastructure` (`httpVersion`, `alpn`, `serverHeader`, `viaHeaders[]`, `proxyLikely`, `proxyEvidence[]`).

**Passive mode (in audit-all):** Header analysis only. **Via / CDN / CF-Ray are context, not findings.** Elevated `risk` only for ambiguous response framing (both TE and CL, or conflicting Content-Length).

**MCP:** `browser_security_smuggling` (same parameters; JSON text with `verdict` first).

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
Shadow — continuous ambient analysis on every navigation. **Off by default** at startup (turn on in Settings → Experimental or POST `enabled: true`). When on, factory audits: **`xss`**, **`retire-js`**, **`security-headers`** (Document response already in the network log — no extra HEAD/GET), **`network`** (HTTP 500 Medium, 404 Low, Content-Length >1 MB / >2 MB Info, duplicate METHOD+URL in one navigation Low only when that URL was fetched from the network twice — disk/memory/prefetch/service-worker hits do not count, nor do 304s for script/stylesheet/image/font; POST/PUT/PATCH/DELETE always count), **`console`** (errors Medium; warnings/info/log ignored). GUI notifications on. Scope **same-origin**. Off unless enabled: **`wcag`** (axe-core), cookies, mixed-content, source-maps, storage. Named pack **`all`** is headers, cookies, xss, mixed-content, source-maps, storage, **retire-js** — it does **not** include wcag/network/console. XSS Shadow skips SRI / third-party-script and other CSP hygiene (`inline-handler`, `inline-script`, `dangerous-sink`); those remain on `POST /api/security/xss`. A new navigation cancels the previous page's in-flight audit batch. **Deduplication** merges findings by `audit + title` across all pages — the same issue (e.g. "No CSP") seen on 7 pages appears once with `occurrences: 7`, a `seenOnUrls` list, and unique `seenOnDomains` (pages on the same host are collapsed). Live traffic still flags sensitive data in URLs and, on Fetch/XHR/Document bodies (bounded size), **SQL error signatures**, **credential/PII-like patterns**, and **CAPTCHA challenge + answer-like fields**. When active, summary included in `GET /api/state` → `securityShadow`.

**POST — Enable/Configure:**

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable or disable. Product starts **off**; omit this field on POST to turn Shadow on |
| `audits` | `["xss","retire-js","security-headers","network","console"]` | Factory default. Named pack `all` = headers, cookies, xss, mixed-content, source-maps, storage, **retire-js** (not wcag/network/console). Or list named audits (`wcag` is opt-in) |
| `scope` | `"same-origin"` | `same-origin`, `all`, or URL pattern |
| `suggestions` | `true` | Generate proactive testing suggestions |

**GET — Query findings:**

| Param | Description |
|-------|-------------|
| `?status=true` | Counts only (lightweight poll) |
| `?since=<id>` | Findings newer than this ID |
| `?severity=high` | Min severity: `info`, `low`, `medium`, `high`, `critical` |
| `?category=headers` | Filter by audit category |

**GET** is **gate-free**. **MCP:** `browser_security_shadow`.

**POST — Laws (Shadow extension):** When `laws` is true (default in settings), Shadow Light/Heavy also evaluates user and embedded **Law** delegates (compiled `.csx` invariants). Optional fields (omit to leave unchanged):

| Field | Description |
|-------|-------------|
| `laws` | Enable Law evaluation alongside built-in audits |
| `disabledLaws` | Law ids to mute |
| `activeLawSources` | Law source keys to run in Shadow (`embedded:…` or full user path). Omit to leave unchanged; JSON `null` restores legacy “all loaded files”. |
| `lightQuicktests` | Embedded quicktest **leaf names** to run in Shadow Light (must be listed explicitly; `@shadow light` alone does not auto-run) |
| `heavyQuicktests` | Quicktest leaf names for Shadow Heavy |
| `runHeavyAfterQuicktest` | Run Shadow Heavy after each Script Console run |
| `serendipityTimer` | Periodic Shadow Heavy |
| `serendipityIntervalSeconds` | Base interval for serendipity timer |
| `lawsMining` | Passive JSON field observation → Law proposals |

### POST /api/shadow/check
Run **Shadow Heavy** now on the UI thread: all page-fact Laws — `OnPage`, plus `OnAction` and `OnTimer` Laws, which run **only** in Heavy — and the configured heavy quicktests (read-only `@effects none` ones only). **MCP:** `browser_shadow_check` (lists non-passing Laws with evidence).

Response includes `message` (`SummaryLine`), `ran`, `lawsEvaluated`, `lawPasses`, `lawFailures`, `lawNotApplicable`, `lawErrors`, `heavyQuicktestsRun`, `pageUrl`, optional `skippedReason`, and `results[]` (non-passing Laws only — **Fail** and **Error**; **NotApplicable** is counted in `lawNotApplicable` but omitted from `results[]`: `name`, `verdict`, `severity`, `message`, `evidence`, `source`).

**Shadow Light** (after each navigation of the active tab) evaluates `OnPage` Laws within `LightLawBudgetMs`. A newer navigation cancels a pending run. Laws that do not fit in the budget are reported as one aggregated Info finding (`audit: law-budget`). Response/console Laws run as traffic arrives. DOM facts for all applicable Laws are fetched in a single page round trip. `.Confirm()` re-reads facts after ~250 ms before reporting a failure.

### Laws: sandbox and safe mode
Law code is compiled and checked against an **allowlist** before it ever runs. It may use LINQ, collections, strings, math, `Regex`, `System.Text.Json` read types, and the Law fact types. It may not use `#r`/`#load`, I/O, networking, processes, reflection (`GetType()`, `typeof(...).Assembly`), threading (`Task.Run`), or `Environment`. Code that fails compilation or the sandbox is never executed, including by `validate`. When an edited user file fails to compile, the last good version stays loaded and the errors appear in `diagnostics[]`.

`--safe` blocks Law **code** operations: `POST /api/laws/validate|add|replace|delete|author|proposals/accept` and the matching `browser_laws` actions (`validate`, `add`, `replace`, `delete`, `author`, `accept`). These remain allowed: `list`, `check`, `proposals`, `reject`, and `POST /api/shadow/check`.

### Built-in Law pack
Embedded Laws (Quicktests → Laws) are always **loaded**; choose which Law **files** run in Shadow with `activeLawSources` (Shadow → Laws tab) or mute individual Laws with `disabledLaws`. Generic embedded Laws report at **Low/Info**:

- **WebPhysics** — the document has a title.
- **GenericWebLaws** — `html[lang]`, viewport meta, `img` missing `alt` attribute (empty `alt=""` is allowed), rendering leaks in visible text (`[object Object]`, `NaN`, unrendered `{{x}}`/`${x}`), password fields on plain-HTTP pages other than localhost, server stack traces in responses, and framework dev-mode warnings in the console.
- **RequiredForbiddenStrings** — forbidden error-UI strings, plus an editable template of required strings.

The user-folder seed `ExampleLaw.csx` contains commented business-invariant examples: cart arithmetic, API contracts, and cookie flags.

### GET /api/laws
List loaded Laws and compile diagnostics (`laws[]`, `diagnostics[]`).

### POST /api/laws/validate
Body: `{ "code": "<Law .csx C#>" }` → `{ "valid", "errors" }`. The code is compiled and checked by the sandbox. It runs once, against a throwaway registry, only if both checks pass. Blocked in `--safe`.

### POST /api/laws/add
Append Law source to `Documents\Trowser Quicktests\Laws\{fileName}` (default `custom.csx`) and reload. Strips trailing `await CheckLaws()` / `AssertLaws()`; validates merged file and rejects duplicate Law **names** already loaded from other files.

### POST /api/laws/replace
Overwrite a user Law file: `{ "fileName", "code" }` → `{ "valid", "path", "errors?" }`.

### POST /api/laws/delete
Delete a user Law file: `{ "fileName" }` or `{ "path" }`.

### POST /api/laws/check
Run Laws on the UI thread: `{ "nameFilter?", "allLoaded": true, "includeTraffic": false }` → `{ "passed", "failed", "results[]", "responseEntriesChecked?", "consoleEntriesChecked?" }`.

Each result includes `verdict`, declared `severity`, and `detail` (failure message plus fact evidence). Set `includeTraffic: true` to evaluate response/console Laws against the captured network and console buffers without re-navigating. Syncs Shadow Law findings (clears stale failures when Laws pass).

### GET /api/laws (last run)
Each Law includes `lastVerdict`, `lastFailDetail`, and `lastFailUrl` when it last failed.

### POST /api/laws/author — mode `fromfinding`
`{ "mode": "fromfinding", "fromFinding": <shadowFindingId> }` → `{ "valid", "code", "errors", "title" }` scaffolds a Law from a Shadow finding (noopener, clickjacking, h1, or a TODO stub).

`Site("host", "/path/*")` sets a default `OnPage` path for Laws in that file that omit `.OnPage(...)`.

### GET /api/laws/proposals · POST /api/laws/proposals/accept · POST /api/laws/proposals/reject
Mined or authored **proposals**. Accept appends to user Laws (`host.csx` for mining source) and reloads. Body for accept/reject: `{ "id": "<proposalId>" }`. Unknown or already-removed ids return **404** on accept and reject (reject does not add ids to the rejected-mining blocklist unless a pending proposal was removed).

### POST /api/laws/author
Natural language → Law source with compile/refine loop (uses configured LLM when available).

| Field | Description |
|-------|-------------|
| `text` / `prompt` | Invariant description (`mode` default `author`) |
| `mode` | `author`, `context` (same as author), `refine` (`code`, optional `notes`), `explain` (`lawName`, `detail`/`failure`) |

Response: `{ "valid", "code", "errors" }` or for `explain`: `{ "explanation" }`.

**MCP:** `browser_laws` with `action`: `list`, `check`, `proposals`, `validate`, `author`, `accept`, `reject`, `add`, `replace`, `delete`. Proposals include `rationale`, `evidence`, and `kind`. `browser_scripting_help` topic `laws` mirrors scripting usage.

### POST /api/security/shadow/clear
Clear accumulated findings. Optional: `{ "category": "headers" }`.

### GET /api/shadows · POST /api/shadows
**Shadows (testing aids)** — **Power mode** reveals hidden/disabled UI for manual testing (optional Phase 2 overlays: outlines and labels). **Red Team Whisper** emits **clues** (hypotheses, not findings) after navigation (DOM + light network heuristics) and once per new domain (tech stack, cache). Duplicate clues are not toasted again in the session. Topics already covered by Shadow (CSP, cookies, XSS, mixed content, source maps, storage, Retire.js, sensitive URLs) are omitted. Optional GUI toasts when `notifyGui` is on; **Copy** on the toast includes dig-deeper details. **Chat-UI clues** require a corroborating signal (known widget global such as Intercom, or an LLM-like network endpoint using the same matching as `llm-endpoint-discover`) — a comment, FAQ, or search textarea alone is not enough.

**GET** returns current settings: `powerMode` (`enabled`, `showOverlays`), `redTeamWhisper` (`enabled`, `notifyGui`, `lastHints`, `clues`, `newClues`).

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
| `probes` | default CSP set | CSP probe ids. Omitted runs the in-page set: `inline-script`, `eval`, `event-handler`, `nonce-reuse`, `base-uri-injection`, `script-src-data`, `script-src-blob`. An explicit list replaces that set. Opt-in only when named: `javascript-url`, `form-action`, `frame-src`, `worker-blob` (these can navigate a hidden frame or start a worker). `probes` does not change SRI, sandbox, or Permissions-Policy. Unknown names come back in `unknownCspProbes`. |
| `verbose` | `false` | When `true`, includes full per-defense `defenses` with every `findings[]` and `tests[]` entry (evidence, long `detail` strings). When `false` (default), returns a **compact** `results[]` and a multi-line `summary` only. |

CSP tests: inline script, `eval()` (reported `not-applicable` when the inline script itself did not run), event handlers, nonce reuse, `<base>`, `data:` script, `blob:` script. Opt-in: `javascript:` URL, `form-action`, `frame-src`, `blob:` Worker. SRI: third-party scripts without integrity. Sandbox: sandbox escapes, missing sandbox on cross-origin iframes. Permissions-Policy: restricted API verification. Compact rows include `result`: `blocked`, `bypassed`, `not-applicable`, or `absent`. `blocked: false` with `result: "not-applicable"` means the probe did not measure that directive.

**Default response:** `elapsedMs`, `overallVerdict`, defense counts, `results[]` rows `{ test, blocked, result, method, category }`, optional `unknownCspProbes`, and `summary` (string). **Verbose response:** same counts + `defenses: { csp, sri, sandbox, permissionsPolicy }` with full `findings` / `tests` (including all per-asset SRI lines).

**MCP:** `browser_firewall_test` (returns the same JSON shape as the REST `data` object, not a plain-text report).

### POST /api/security/client-surface
Client-side attack-surface map (browser-native sibling of `/api/security/attack-surface`). Aggregates runtime sensor events (sources, sinks, listeners), DOM facts (`target=_blank` without `noopener`, clobber candidates, iframes, storage **key names**), service worker registrations / Cache Storage names / IndexedDB database names, source×sink cells (`tested`/`untested`), **`domFlows`** (source→sink→consequence chains), a **`risks`** checklist, and **`nextActions`** derived from the pursue, lead, and manual rows.

**`risks[]`** is triage, not a scan. Each row is one browser-side class with `status`:

| Status | Meaning |
|--------|---------|
| `pursue` | Preconditions showed up on this page. Run `followUp`. |
| `lead` | Something is present, or the sensor did not see the load. Look before skipping. |
| `manual` | This map cannot clear the class (client-side authorization, frontend business logic). |
| `not-observed` | Required evidence was missing (empty runtime, truncated external script, no document headers). Not a clearance to skip. |
| `dismiss` | On the evidence collected, skip the follow-up scanner. |

`dismiss` is not a finding, and it is not proof for a route the sensor never saw. An empty runtime log leaves sink-based classes at `lead` (`coverage.zeroResultReason`); several header/script-dependent rows become **`not-observed`** instead of dismiss when `coverage.surfaces.scriptSurfaceIncomplete` is true. **`coverage.surfaces`** reports runtime, inline script, external script log vs scan counts, document headers, and DOM framework hints (e.g. `ng-version=`). Storage values are not read — only key names. The checklist does **not** run XS-Leaks, DOM XSS probes, gadget chains, CSTI, or the postMessage audit.

Classes, in order: XS-Leaks, DOM XSS, client-side CSRF, postMessage, client-side prototype pollution, DOM clobbering, DOM open redirect, client-side authorization, client-side HTML injection, client-side template injection, web storage, frontend business logic, reverse tabnabbing, XSSI, service workers, clickjacking, CORS, CSS injection, dangling markup, Trusted Types, WebSocket.

A **dismiss** for DOM XSS or DOM open redirect means the sink was not seen at runtime and is not in the page script either. CSTI **pursue** includes DOM `ng-version` hints and template compilation in script. XS-Leaks stays **manual** when the only signal is missing COOP/COEP/CORP; it becomes **lead** when the page loads a cross-origin image, script, or frame, or the log already has two different responses for the **same method and path** (GET vs PUT on one path is not a state pair). **Reverse tabnabbing:** missing `rel=noopener` on `target=_blank` anchors is **manual** hygiene (implicit noopener in WebView2/Chromium); `window.open` without noopener in script stays **lead**. Storage reasons say whether a key was touched by this document or left on the origin by an earlier navigation. Service-worker **pursue** means this document calls `register`; a worker that is already controlling the origin is **lead** and names the controlling script URL. WebSocket `message` listeners are not filed as postMessage.

`riskSummary` counts pursue, lead, manual, **notObserved**, and dismiss. **`nextActions`** repeats follow-up text for pursue, lead, manual, and not-observed rows (dismiss stays out). **`dom.tabnabbing[]`** entries include `navigationKind`, `missingExplicitRel`, and `effectiveOpenerPolicy`.

| Field | Default | Description |
|-------|---------|-------------|
| `installSensor` | `true` | Install the shared runtime sensor if needed |
| `waitMs` | `400` | Settle wait before reading the event log |
| `reloadForSensor` | `true` | Reload once after installing the sensor so page scripts run under hooks |
| `reset` | `false` | Clear the runtime sensor buffer for this document scope before mapping |
| `scopeToCurrentDocument` | `true` | When `false`, include session history from earlier navigations on the origin |

**MCP:** `browser_client_surface` (security pack). **Quicktest:** `2 ClientSurface`.

### POST /api/security/service-worker-audit
Browser-native **service worker** review on the **current origin** (callable without running client-surface first). Enumerates `navigator.serviceWorker.getRegistrations()`, the controlling worker, and Cache Storage names; optionally **fetches worker script bodies** in-page for static flags (`importScripts`, `fetch` event handler, `cache.put`, `clients.claim`). Emits scope/script hygiene **`findings[]`**, document **`trustedTypes`** from the current document’s response headers, and **`nextActions`**.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `safe` | Requires `safe` or higher (`passive` is rejected) |
| `fetchScripts` | `true` | Fetch each worker `scriptURL` for byte-limited static review |
| `maxScriptBytes` | `256000` | Cap per script (4096–512000) |

Does not register or update workers. For triage only, client-surface **service workers** row points here via `nextActions`.

**MCP:** `browser_security_service_worker_audit` (security pack).

### POST /api/security/xssi-scan
Cross-Site Script Inclusion (XSSI) and **JSONP exposure** assessment from the **network log** plus optional explicit URLs. Re-**GET**s each candidate with **browser session cookies** and flags responses that look **includable as cross-site script**: JSON **arrays** served without `X-Content-Type-Options: nosniff`, `text/javascript` bodies that start with `[` or assign to a global, and **callback wrappers** (`callback` / `jsonp` / `cb` query params with matching `name(` in the body). Does **not** run a mocked attacker-origin `<script src>` proof — findings are **hygiene** tier (`tier: hygiene`); use manual or custom workflow to confirm data read from another origin.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `safe` | Requires `safe` or higher (`passive` is rejected) |
| `urls` | — | Optional explicit absolute URLs (when set, only these are probed) |
| `maxUrls` | `12` | Cap on URLs from log or `urls[]` (max 30) |
| `timeoutMs` | `12000` | Per-URL GET timeout |
| `includeNetworkLog` | `true` | When `urls` omitted, collect script/json/jsonp-hint URLs from the session log |

**Response:** `message`, `urlsProbed`, unified `findings[]` (`category: xssi`), `nextActions` (often `POST /api/security/headers` and client-surface).

**MCP:** `browser_security_xssi_scan` (security pack). **Quicktest:** `2 XssiScan`. Client-surface **XSSI** row **`lead`** points here when the log shows JSON arrays without nosniff or JSONP-shaped script responses.

### POST /api/security/postmessage
Enumerate `message` listeners (runtime sensor + CDP), grade origin checks (`none` / `weak` / `strict` / `unknown`), **screen** with synthetic `MessageEvent`s (never filing-grade **critical**), and **confirm** at `active`/`aggressive` with mocked attacker-origin **technique** probes (`child-iframe` by default; `depth: deep` adds popup/framed topologies). Correlates **outbound** `postMessage` / `window.name` from the session log when OAuth traffic exists. Returns **`techniques`**, **`posture`**, **`runId`**, **`coverage`**, **`nextActions`**.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `safe` | `safe` = synthetic screen; `active`/`aggressive` = trusted cross-origin proof |
| `fuzz` | `true` | Dispatch synthetic MessageEvents |
| `maxPayloads` | `8` | Max fuzz payloads (1–20) |
| `maxPayloadsPerListener` | `2` | Schema-matched payloads per listener for active proof |
| `depth` | `quick` | `quick` = child-iframe only; `deep` = extra topologies |
| `suggestOnly` | `false` | Listeners + inferred schemas only (no fuzz) |
| `includeOutbound` | `true` | Harvest outbound leaks from runtime log |
| `maxSeconds` | `0` | Wall-clock budget (0 = none) |
| `listenerFilter` | — | Substring on `listenerId` or handler preview |
| `topologies` | — | e.g. `child-iframe`, `popup-to-opener`, `framed-target` |
| `includeHistory` | `false` | Include listeners from session history, not only the current document |
| `reset` | `false` | Clear the runtime listener log before enumerate |
| `descendIframes` | `true` | When the top document has no listeners, walk same-origin iframe `src` URLs |
| `attackerOrigin` | — | Override mocked attacker origin for active proof |

**MCP:** `browser_postmessage_audit` (security pack; same parameters).

**Session / tabs (active runs):** Same popup lifecycle as XS-Leaks — `sessionLostDuringScan`, `popupTabsOpened`, `orphanPopupTabsClosed` on the response (plus `budgetExhausted` when capped).

**Finding extras (active runs):** When every `techniques[]` row for a static hygiene `listenerId` is blocked (`confirmationStatus: none`), matching **`findings[]`** hygiene rows are demoted (typically **info**) with `extra.activeConfirmation: "blocked"` and `extra.caveat` (self-contained triage). Synthetic screen uses control vs bypass origin **differentials** (`extra.differential`).

### POST /api/security/client-prototype-pollution
Client-side prototype pollution via URL query/hash and postMessage canaries, then optional gadget→sink escalation. **Separate from** server-side `POST /api/security/prototype-pollution-scan`.

**Safety gate:** Requires `"safetyMode": "active"`.

| Field | Default | Description |
|-------|---------|-------------|
| `baseUrl` | current page | Base URL to probe |
| `tryGadgets` | `true` | After pollution, try a small gadget table toward sinks |

**MCP:** `browser_security_client_prototype_pollution`.

### POST /api/security/dom-flows
Answer: “where does attacker-controlled data become executable or security-sensitive DOM state?” Builds chains `{source, value, sink, mutation, consequence, confidence}` from the runtime sensor (value-match / canary preferred over temporal heuristics).

| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `observe` | `observe` (passive) or `probe` (plant canaries; requires `safetyMode: active`) |
| `waitMs` | `400` | Settle wait for observe |
| `waitForSpa` | `true` | After navigation/probe, wait for idle plus common SPA roots (`app-root`, etc.) |
| `sources` | common set | Probe sources: `url-query`, `url-hash`, `storage`, `window-name`, `post-message`, `indexeddb` |
| `canary` | auto | Optional canary string for probe mode |
| `minTier` | `hygiene` | Filter chains: `noise`, `hygiene`, `probe-artifact`, or `exploitable` |
| `restoreUrl` | `true` | After probe, restore the pre-probe URL and remove probe `localStorage` keys |
| `reset` | false | Clear the runtime sensor event buffer **without** `clear-all` (cookies/network unchanged). Use before `observe` for a clean page-local read. |

Each chain includes `tier` (`noise` / `hygiene` / `probe-artifact` / `exploitable`) and `consequence` (sink **capability** class — `exec` means the sink type can execute script/markup, not that attacker execution was observed in this run). Additional consequence labels include **`css-injection`** and **`dangling-markup`** for stylesheet / incomplete-tag exfiltration classes when the sensor sees matching sinks. Response includes **`trustedTypes`** (CSP `require-trusted-types-for` / `trusted-types`) for triage alongside chains. **`exploitableChainCount`** counts attacker-reachable sources only (URL/hash/postMessage/storage — not `document.cookie` session plumbing or third-party iframe widgets). **`observe`** slices events recorded **since the start of that call** (not the full session buffer). **`reset: true`** clears accumulated sensor history when you need a fresh observe after other probes. Hash-router SPAs (e.g. `#/search?q=`) get fragment-aware query probes automatically; **probe mode** mutates query/hash keys already on the URL (plus runtime discovery) before synthetic fallbacks like `trowser_q`. **Storage probe** sets `localStorage.trowser_probe` and reloads the page (no Trowser `innerHTML` injection) — exec findings require a page script in the stack. **Typical runtime:** observe ≈ 1–5s; probe with multiple sources ≈ 10–40s.

**MCP:** `browser_dom_flows` (security pack).

**Window-name / indexedDB probes:** Set `window.name` or seed IndexedDB, then **reload** so application code reads the value (no Trowser-side `innerHTML` scaffolding).

### POST /api/security/gadget-radar
Runtime **gadget radar**: logs missing-global reads on `window`/`document` (non-perturbing; installed with Ambient runtime sensor / Shadow `runtime` audit) and optional perturbing `Object.prototype` getter traps (explicit session only).

| Field | Default | Description |
|-------|---------|-------------|
| `action` | `read` | `read` \| `start` \| `stop` |
| `perturbing` | `false` | When `action=start`, install proto-read getter traps (requires `safetyMode: active`) |
| `protoKeys` | auto | Keys for perturbing traps |

**MCP:** `browser_gadget_radar`.

### POST /api/security/gadget-chains
XS-Leaks-style orchestrator for **client-side gadget chains** (DOM clobbering, client PP, DOM XSS flows): ranks radar hits, plans probes, runs tailored clobber / client-PP / dom-flow probes with confirmation. Clobber URL injection should prefer **query/form field names** from **`client-surface`** / inline script discovery (not only generic names like `q`) — pass `queryParam` on follow-up **`trace-input`** when the orchestrator log shows a mismatch.

Response includes **`findings`** (confirmed chains only) and **`leads`** (radar hits, tentative DOM flows, non-confirmed PP — follow-up hints, not auto-filed vulns). Clobber injection runs only for **trap-based** missing-global reads (not script-scan or built-in `document.*` names). DOM-flow **findings** require exec/canary or markup/nav/forgery with a page script in the stack; inert `value-match` chains stay in `leads`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | required `active` | Active probes mutate navigation / prototype |
| `probes` | planner | Subset: `clobber`, `client-pp`, `dom-flow-probe` |
| `maxSeconds` | `0` | Wall-clock budget |
| `includeRadar` | `true` | Ensure radar before scan |
| `targetGlobals` | radar | Override clobber probe names (built-ins filtered) |
| `perturbingRadar` | `false` | Proto getter traps during scan |

**MCP:** `browser_security_gadget_chains`.

### POST /api/security/xs-leaks
Cross-site leak differential scanner. Constructs an attacker context (`https://evil.trowser.test/xsleak/...` via mocks) and asks whether an attacker can distinguish victim **states** using load/error, frame count, media, timing, redirect-type (`fetch-redirect-type`), cache hints (`resource-transfer-size`), popup, and postMessage observables. Does not read cross-origin response bodies. Returns unified `findings`, optional watermarked `pocHtml` (session evidence), `posture` (COOP/CORP/COEP / Fetch Metadata hints), and `browserModel` (WebView2 assumptions).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | required ≥ `safe` | `safe` = GET-ish techniques; `active` enables popups + higher-trial timing |
| `states` | — | Optional `[{label, url, identity?, setupUrl?, role?, method?, form?, body?, contentType?}, ...]`. **When omitted or fewer than two entries, states are auto-derived** (same as `autoStates: true`). `role`: `hit` \| `miss` \| `control`. Use **POST** + `form` for search forms (see example below). |
| `hypothesis` | — | Optional `{ secret, kind?, method?, urlTemplate?, formFields?, bodyTemplate?, contentType?, hitValues?, missValues? }`. Placeholder **`{value}`** in urlTemplate, formFields, or bodyTemplate. **Omit `states[]`** — only `hypothesis` + hit/miss values is enough when urlTemplate is set. Default **autoStates:false** when hypothesis is set. Echoed in `details.hypothesis` (`requested`, `expanded`). **`role` on explicit states** sets `requested:true` and enables screening/confirmation even without a `hypothesis` object. |
| `suggestOnly` | false | Return `details.suggestedHypotheses` (empty array if none) **without running probes**. |
| `autoStates` | true when no states/hypothesis | Set **false** when using `hypothesis` (default). If true with hypothesis, auto-states can override expansion (warning emitted). |
| `autoStates` | **true when `states` omitted** | Derive from **identities on the same host**, **search hit/miss only when session traffic shows status or body-length delta**, or protected vs synthetic miss. Set `false` to require two explicit states. |
| `attackerSite` | `cross-site` | `cross-site` → `https://evil.trowser.test`; `same-site` → `https://evil-samesite.{victimHost}` (mocked sibling for SameSite/cache experiments) |
| `techniques` | planned subset | When omitted, a **session-aware planner** picks a small set from `details.plan` (server diff + observed cookie delivery). Filter by id/category, or set `fullCatalog: true` for the full catalog. |
| `fullCatalog` | false | Run the entire safe/active technique catalog (slow on WAN targets). |
| `budget.maxSeconds` | 0 (none) | Stop early with `details.budgetExhausted: true` and partial technique results. |
| `safetyMode: active` | — | Also enables `cache-prime-probe`, `connection-pool-exhaustion`, `popup-closed` (resource-cost / popup techniques) |
| `trials` | per-technique | Override trial count |
| `skipWarmup` | false | Skip one warm-up trial round per state |
| `includePosture` | true | Isolation posture block (COOP/CORP/Fetch Metadata/SW). Set `false` for oracle-only runs. |
| `postureInteractionProbes` | active default | In `active` mode, live **COOP opener** and **Fetch Metadata enforcement** probes (HttpClient with `Sec-Fetch-Site: cross-site`). Omit or set `false` to skip. Hypothesis runs default this to **false** unless you set it explicitly. |
| `observeMode` | false | Phase 2: record AutoLeak-style observation vectors per state in `details.observe` (no severity). |
| `identifyAuthCookie` | false | Active only: reserved for leave-one-out auth cookie ID (currently advisory note only). |

Probe tabs copy mock rules from the active tab so offline fixtures apply to cross-origin subresource loads.

**Hypothesis mode** (explicit `hypothesis`, `role` on states, or expanded template) runs **screening** (first hit × first miss, 3 trials) then **confirmation** (+3 trials and a same-role **control** miss when a second miss value exists). Technique rows include **`confirmationStatus`**: `confirmed` / `confirmed-mitigated` / `candidate-*` / `none`. Only **`confirmed*`** emits an exploitable **`findings[]`** entry; candidates stay informational. Evaluation is **hit × miss** only when roles are set. Default wall-clock budget is **60s** when `budget.maxSeconds` is omitted. If the planner finds **no eligible techniques**, the summary is **`Not tested:`** (not “0 distinguishable”).

`details.sameUrlStates: true` means all states share the same **request target** (URL + method + body/form), not merely the same path. Same path with **different POST JSON bodies** → `sameUrlStates: false`; use `form-post-frame` and related probes. When `sameUrlStates: true`, **timing/cache techniques are omitted**. **Do not trust the top-level `message` alone** when `sameUrlStates: true` — read **`details.stateValidation.credentialedDiff`** first (the summary can undersell a server-side diff). **Typical runtime:** default quick catalog ≈ 30–90s on lab hosts; **full catalog on external targets** often **3–15+ minutes** — use `fullCatalog: true` only when needed, or `budget.maxSeconds` / explicit `techniques`. Technique rows may include `applicability: low` when the probe cannot apply (e.g. `img-error` on JSON APIs).

Techniques (full catalog in `XsLeakTechniques`): load/error (`img-error`, …), navigation (`form-post-frame` for POST form states), redirect/status, popup/window (`popup-closed`, `window-open-length`, `named-window-reuse`, `history-length-delta`, …). In **`safetyMode: active`**, the default planner also adds **popup/top-level** probes (not only the 5-technique safe quick set). Use `fullCatalog:true` for every catalog entry. Confirmed differentials attach watermarked PoC HTML in `findings[].extra.pocHtml` and register matching **`xs-leak-poc`** rows in the session VPX artifact feed on export.

**Hypothesis example (GET search):**

```json
{
  "safetyMode": "safe",
  "hypothesis": {
    "secret": "Ulcerös proktit appears in search results",
    "kind": "diagnosis",
    "urlTemplate": "https://app.example/search?q={value}",
    "hitValues": ["Ulcerös proktit"],
    "missValues": ["zzzznonexistentdiagnosis99"]
  }
}
```

**POST search (HTML form, `application/x-www-form-urlencoded`):**

```json
{
  "safetyMode": "active",
  "hypothesis": {
    "secret": "Diagnosis in POST search results",
    "method": "POST",
    "urlTemplate": "https://app.example/search",
    "formFields": { "q": "{value}" },
    "hitValues": ["Ulcerös proktit"],
    "missValues": ["zzzznonexistentdiagnosis99"]
  },
  "techniques": ["form-post-frame", "status-bucket-oracle"]
}
```

**POST search (JSON REST — same URL, body differs):**

```json
{
  "safetyMode": "active",
  "hypothesis": {
    "secret": "Case list differs when personnummer has an open case",
    "method": "POST",
    "urlTemplate": "https://app.example/api/cases/search",
    "contentType": "application/json",
    "bodyTemplate": "{\"personnummer\":\"{value}\"}",
    "hitValues": ["201001011234"],
    "missValues": ["201001019999"]
  }
}
```

Or explicit states (hypothesis pipeline + `confirmationStatus` without a template object):

```json
{
  "safetyMode": "active",
  "states": [
    { "label": "hit", "role": "hit", "url": "https://app.example/api/search", "method": "POST", "contentType": "application/json", "body": "{\"q\":\"secret\"}" },
    { "label": "miss", "role": "miss", "url": "https://app.example/api/search", "method": "POST", "contentType": "application/json", "body": "{\"q\":\"zzzz\"}" }
  ]
}
```

`autoStates` considers **GET query** pairs and **POST same-URL body** pairs when session traffic shows status or response-length delta (≥32 bytes).

Response always includes **`details.stateValidation`** / **`details.hypothesisValidation`** (alias), **`details.sessionProfile`**, **`details.credentialDelivery`**, **`details.plan`**, and **`details.hypothesis`**. Before probes run, nested objects may show `detail/note: "not-run"`. **`details.warnings`** includes SameSite exploitability notes when cookie delivery was observed. The scan **captures and restores** site-scoped cookies/storage (scripting: `BrowserSessionCaptureAsync` / `BrowserSessionRestoreAsync`).

Response `details.authModelNotes` warns when identities are **JWT/localStorage-only** (subresource probes do not send `Authorization`) or when an identity **domain does not match** the victim URL host. `posture` may include **CORS-wildcard**, **CORP/COOP effectiveness**, **Service-Worker-cache**, and **Fetch-Metadata-enforcement** when interaction probes run. `details.chainAnalysis` lists pattern-matched chains (e.g. `xs-leak-side-channel-cors-read`). When session traffic shows wildcard/reflected CORS on the same endpoint as an **exploitable** XS-Leak finding, `chainFindings` includes **`xs-leaks+cors`** and `details.corsChainedCount` is set.

**MCP:** `browser_security_xs_leaks`. Blocked in `--safe` (uses mocks).

**See also:** orchestrated sweep — `POST /api/orchestrate/a14-other` (includes an XS-Leaks step after cache/smuggling probes). Described in [SecurityTestingWithTrowser.md](SecurityTestingWithTrowser.md) (Trowser Twelve / `a14-other`).

**Auth cookie ambiguity:** when `sessionProfile.authCookies` lists both CSRF and session cookies, `credentialDelivery.authCookieName` is the **gating session cookie** candidate (not `authCookies[0]`). To prove which cookie/header gates the API, run **`POST /api/security/auth-control-identifier`** (`safetyMode: active`) on the victim endpoint first (GUI: *Identify auth controls* on the request editor).

**Session safety:** state URLs matching logout/sign-out paths are rejected. Security probes skip those URLs by default. Active scans set `details.sessionLostDuringScan: true` and stop if auth cookies are cleared, the **home tab** lands on a logout URL, or the home tab navigates to a known IdP/SSO step-up host (off-victim). Probe `window.open` popups are agent-owned, open in the background during MCP/REST, and are auto-closed at scan end (`details.popupTabsOpened`, `details.orphanPopupTabsClosed`). Popup/window techniques are skipped when validation shows a logout final URL.

### POST /api/security/trace-input
Input→Network→DOM causality tracing. Supports multiple **injection sources**: form field (type+submit), **url-query**, **url-hash**, **url-path**, plus client-runtime sources **window-name**, **storage**, **post-message**, **referrer**. Identifies input **filtering vs encoding** (not “sanitization = safe”), server reflection context, **open redirects** (HTTP 3xx with external Location — CWE-601), DOM rendering, CSP, and sink reachability via **canary taint** (payload markers in sink arguments — not full JS dataflow). **Context-aware reflection:** `javascript:` / `data:` URIs are only flagged dangerous in URL attributes — not plain text. DOM analysis uses payload **markers** and dangerous-element detection.

When a **form control filters or constrains** input (e.g. `<select>` truncates payload), the tool does **not** report safety — it notes the coverage gap and, with **`probeUrlSources: true`** (default), automatically probes **url-query** and **url-hash** after form bypass attempts fail.

**Safety gate:** Requires `"safetyMode": "active"`. Blocked in safe mode.

| Field | Required | Description |
|-------|----------|-------------|
| `source` | No | `form` (default), `url-query`, `url-hash`, `url-path`, `window-name`, `storage`, `post-message`, `referrer` |
| `target` | Yes‡ | CSS selector for input element (**required when `source=form`**) |
| `baseUrl` | No | Base URL for url-* / referrer sources (default: current page URL) |
| `queryParam` | No | Query param name for `url-query` (default `q`) |
| `hashParam` | No | Hash param for `url-hash` — omit to use payload as **entire fragment**, or let Trowser **auto-discover** param names from inline scripts (e.g. DVWA `default=`) |
| `storageKey` | No | Key for `source=storage` (default `trowser_probe`) |
| `storageKind` | No | `local` (default) or `session` for `source=storage` |
| `queryEncode` | No | `none` (default — raw for DOM XSS via decodeURI/decodeURIComponent), `component`, `form` |
| `fragmentEncode` | No | `none` (default — use for DOM XSS hash bypasses), `component`, `form` |
| `pathEncode` | No | `component` (default), `form`, `none` |
| `probeUrlSources` | No | After form filtering, auto-probe url-query + url-hash (default `true`) |
| `payload` | One of* | Single payload. With `autoBypass: true`, omit to use default `<script>alert(1)</script>` |
| `payloads` | One of* | Array of payloads (batch). **Not compatible with `autoBypass`** |
| `autoBypass` | No | Try alternative **XSS** vectors when primary fails; for url-* sources, retries bypass catalog via navigation (default `true`). When `monitorSinks` lists **navigation sinks** (`location.*`, `window.open`), also tries **open-redirect-style** URL bypass probes (`//`, `/\`, …). |
| `maxBypassAttempts` | No | Max alternative vectors (default `10`, max `15`) |
| `submit` | No | CSS selector for submit button (form source) |
| `submitAction` | No | `click` (default), `enter`, `none` |
| `checkCsp` | No | Evaluate CSP protection (default `true`) |
| `detectSqli` | No | Scan **response bodies** for SQL/DB error signatures (default `false`) |
| `confirmExecution` | No | **Default `false`** (`true` when `safetyMode` is **`aggressive`**). When **`true`**, phase-2 / single-shot traces embed the safe **`__trowser_exec`** / `__xss_proof` oracle. **Auto-enabled** after phase-1 reach on confirmable HTML/eval/navigation sinks even when omitted. Reach-only when no such sink is hit. |
| `monitorSinks` | No | **Default `true`.** Install the shared **runtime sensor** (eval/innerHTML/setAttribute/location/fetch/…, source reads, message listeners) **before** injection. For navigations and reloads (form submit, `window-name`, `storage`, url-*), hooks register via document-created scripts so page scripts run under instrumentation. **Sink reach** (`sinkReached: true`, high severity) is separate from **confirmed XSS** (`confirmedXss: true` only when `sinks.executionConfirmed`, dialog effect, or verified off-site navigation). Set `confirmExecution: true` (or `safetyMode: aggressive`) to upgrade phase-2 payloads with the exec oracle. |
| `extraQuery` | No | Object of extra query keys merged into url-query traces (e.g. `{ "auto": "1" }` for gated client redirects). |
| `twoPhase` | No | When `monitorSinks` is on (default **`true`**): phase 1 injects a plain reach canary and builds `reachMap[]` (sink + page stack); phase 2 picks a context-aware confirmation payload (exec oracle only when `confirmExecution` is enabled). |
| `probeAllUrlParams` | No | For `url-query`: reach-canary every discovered query key (URL + inline hints), then confirm on the best hit. |
| `fireEvents` | No | After navigation, click the first in-page anchor (helps click-gated sinks such as `window.open`). |
| `timeout` | No | Per-trace wait ms (default `10000`). With **`autoBypass: true`**, total wall time is capped (~2× timeout + bypass budget, max ~90s) — not unbounded per attempt. |
| `delayMs` | No | Optional wait before trace starts (default `0`, range 0–120000 ms) |

**Injection (form):** `injection.formInteractionFailed`, `injection.formInteractionFailureReason`, and `injection.targetElementsMatched` report selector misses (`selector matched 0 elements`) instead of burying the failure in `bypassSummary` only.

**Two-phase confirmation:** When phase 1 reaches an HTML sink and the caller's `payload` is a `<script>…</script>` tag, phase 2 picks an event-handler vector (same as `autoBypass`) — explicit script payloads and `autoBypass` should agree on the same target. Prefer **`autoBypass: true`** (default) unless you need a fixed primary string.

\*Provide `payload`, `payloads`, or `autoBypass: true` (with optional primary `payload`).  
‡Not required for url-* / client-runtime sources.

Single response: **`injection`** (`sourceType`, `treatment`, `constraintType`, `encoding`, `navigatedUrl`, `notes`), `network`, `serverResponse` (`openRedirect`, `redirectLocation`, `redirectHost` when 3xx Location points off-site), `dom`, `csp`, `reachMap[]` (optional two-phase reach hits with `pageStack`), `sinks` (optional; includes inventory + optional `classification` on hits: `dom-open-redirect` / `client-request-forgery` / `sanitizer-context`), `sqliIndicators` (optional), `verdict`.

**Auto-bypass response:** `primaryPayload`, `primaryOutcome`, `bypassConfirmed`, `bypassSummary`, `bypassAttempts[]`, **`urlProbeAttempts[]`** (form → URL fallback probes), `worstVerdict`, `effectiveTrace`, `primaryTrace`, optional `successfulBypass`.

Batch response: `summary` + `traces[]`.

**MCP:** `browser_trace_input`.

**Tab URL:** After the trace completes, Trowser **restores the pre-probe page URL** (strips tool query keys such as `_trowser_rc` used for cache-busting navigations). Later scans and snapshots stay on your baseline page unless you intentionally navigated elsewhere.

### POST /api/security/dom-xss-audit
First-class **DOM XSS** pass on the **current page** URL (no network-log sweep). Default **`depth: standard`** is a **medium** profile (~45s wall clock): passive XSS + dom-flow probe + trace-input on **url-hash** and **one** url-query key — not a full query-param sweep. Use **`depth: deep`** for client-surface + `probeAllUrlParams` + script-gated traces. Returns unified `findings[]`, compact `traces[]`, and **`applied`** / **`scanDepth`** echoing what actually ran.

**When to use (vs other XSS tools):**

| Tool | Role |
|------|------|
| **`dom-xss-audit`** (this) | Default **active DOM XSS** pass on the page you are on — bundles passive XSS, dom-flow, and query/hash **trace-input** |
| **`xss-scan`** (alias **`xss-dom-audit`** — not this endpoint) | Reflected/stored **HTTP** XSS from network-log candidates; clean result does **not** cover hash/DOM trace-input depth |
| **`trace-input`** | Single source/param precision, forms, or repro after a finding |
| **`xss`** | Passive patterns only |

**Safety gate:** Requires `"safetyMode": "active"`. Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `depth` | `standard` | **`quick`** (~25s) — passive XSS + dom-flow only; no trace-input unless explicit. **`standard`** (default) — **medium current-page**: passive + dom-flow + hash trace + single query trace (`q`). **`deep`** (~90s) — client-surface, all query keys, script-gated traces; `confirmExecution: true` unless overridden. Aliases: `fast`/`light` → quick; `thorough`/`full` → deep. |
| `confirmExecution` | `false` (`true` when `safetyMode: aggressive` or `depth: deep`) | Phase-2 `__trowser_exec` oracle on trace-input |
| `runClientSurface` | `false` (`true` when `depth: deep`) | Map runtime sources/sinks/listeners and source×sink cells |
| `runPassiveXss` | `true` | Passive DOM XSS + dom-open-redirect click oracle |
| `runDomFlowProbe` | `true` | Active dom-flow canary probe (`restoreUrl: true`) |
| `runTraceInput` | `true` (`false` when `depth: quick`) | url-query + url-hash trace-input legs |
| `probeAllUrlParams` | `false` (`true` when `depth: deep`) | Reach-canary every query key, confirm on best hit |
| `probeUrlHash` | `true` (`false` when `depth: quick`) | Full-fragment hash trace |
| `runScriptGatedTraces` | `false` (`true` when `depth: deep`) | Extra trace-input from inline script redirect/location hints |
| `fireEvents` | `false` | Click first same-page anchor after navigation |
| `timeoutMs` | `6000` (`8000` deep) | Per nested **trace-input** wait |
| `budget.maxSeconds` | `45` standard / `90` deep | **Orchestrator wall clock** — override anytime; partial + `budgetExhausted` when capped |

**Runtime:** Enabled phases run **serially**. `timeoutMs` applies to each trace-input leg; total time can still grow with query-key sweeps and optional client-surface unless capped by **`budget.maxSeconds`**. The orchestrator should honor the gated request **abort token** (client disconnect / `POST /api/abort`) and release the busy gate with partial results. On exit (including partial/budget), the audit **restores the URL** from before the run (same rules as **trace-input** / **csti-scan**).

**Cheaper ladder (when a full audit runs many minutes):**

1. **`depth: "quick"`** on this endpoint (passive + **`dom-xss-flow`** canaries only), or separate **`POST /api/security/xss`** (passive) + **`POST /api/security/dom-flows`** `mode: "probe"`.
2. **`POST /api/security/trace-input`** on the param/source **`dom-xss-flow`** flagged (single sink confirmation).
3. Full **`dom-xss-audit`** (standard/deep) when you need query-key sweep + client-surface + hash traces in one call.

Response highlights: **`scope`** (`current-page`), **`scanDepth`**, **`applied`** (exact phase flags and timeouts used), `summary`, `worstSeverity`, `executionConfirmed`, `nextActions[]`, `findings[]`, `traces[]`, optional **`partial`** / **`budgetExhausted`** / **`elapsedMs`**.

**MCP:** `browser_dom_xss_audit`. **Quick playbook** step `dom-xss-audit` uses this orchestrator (skips duplicate `trace-input`).

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

**Envelope:** `message`, `depth`, `candidatesProbed`, `payloadsSent`, `elapsedMs`, `hasFindings`, `summary[]`, `findings[]`, optional **`progress[]`** (coarse steps for long runs — **xss-scan** logs candidate index and DOM-verify phases), optional `details` (rows/baseline/diagnostics).

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
**Fast reflected SSTI** probe: single GET **polyglot** payload `${7*7}{{7*7}}<%=7*7%>#{7*7}` across common search/render paths and query parameter names. Baseline diff detects evaluated **49** with non-digit boundaries (high when clean; medium with partial markers / template residue). Inspired by OWASP WSTG-INPV-18 and PortSwigger SSTI methodology.

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
**Stored SSTI**: POST template payload to profile-shaped fields (`bio`, `about`, `signature`, …), then **GET readback** URLs for evaluated marker **13289** (`137*97`). Requires marker absent from baseline; POST-echo alone is high, confirmed separate readback is critical. Tests Jinja2 `{{137*97}}`, Velocity `${137*97}`, ERB `<%=137*97%>` via form-urlencoded and JSON. Works best when logged in (`includeBrowserCookies`). Inspired by OWASP WSTG-INPV-18 and PortSwigger SSTI. **Mutates** profile fields under active mode.

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
**Server-side prototype pollution**: POST JSON with **`__proto__`** and **`constructor.prototype`** pollution keys, then **GET** verify paths (`/`, `/api/me`, …) for canary **emergence** (absent on pre-pollution GET, present after). Hard-rejects 400/403/422 on pollution POST. Inspired by OWASP WSTG-INPV-22 and PortSwigger non-DoS PP research.

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
| `escalate` | `false` | Sandbox-escape probes after basic confirmation (multiple filter-bypass variants recommended when basic `{{7*7}}` succeeds — single fixed strings miss naive blocklists) |
| `monitorSinks` | `true` | Hook eval/Function/innerHTML during probes |
| `maxCandidates` | `10` | Max parameter candidates |
| `timeoutMs` | `10000` | Per-navigation wait |

**Response:** `message`, `candidatesProbed`, `enginesTested`, `elapsedMs`, `hasFindings`, `findings[]` (url, parameter, source, engine, basicExpression, evaluatedToken, codeExecution, sinks, severity), `probes[]`.

**MCP:** `browser_security_csti_scan`.

**Tab URL:** Restores the pre-scan URL when the batch finishes (including payload query/hash URLs and `_trowser_rc` cache-bust params).

### POST /api/security/parser-probe
**Parser differential** probe for JSON **POST/PUT/PATCH** endpoints: runs a **Content-Type matrix** (XML, form-urlencoded, multipart valid/missing boundary, java-serialized, text/plain, json utf-7) and **body-shape matrix** (duplicate keys, type confusion, trailing content, json-breaking subset). Flags **`content-type-confusion`**, **`deserialization-suspected`**, **`parser-differential`** for chain analysis.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | Optional explicit `{ url, method?, headers?, cookie?, body? \| json? }` — else discovers from network log |
| `maxCandidates` | `5` | Max JSON endpoints to probe |
| `includeContentTypeMatrix` | `true` | Run Content-Type swap probes |
| `includeBodyShapeMatrix` | `true` | Run body-shape probes |
| `includeBrowserCookies` | auto | When omitted, sends browser jar cookies only if the jar has cookies for the target host; explicit `Cookie` / `Authorization` in `request.headers` (or `request.cookie`) always applies |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `message`, `candidatesProbed`, `probesSent`, `skippedNoSession`, `findings[]` (category, severity, signal, url, probeKind, contentType, bodyVariant, baselineStatus, probeStatus, detail). Endpoints whose baseline is HTTP 401/403 with no session cookies or `Authorization` are skipped (not compared as parser differentials).

**MCP:** `browser_security_parser_probe`. In auto-scan: **`includeParserProbe`** omitted = **auto** when JSON POST endpoints exist; `true`/`false` to force.

### POST /api/security/deserialization-scan
**Deserialization scan** for JSON sinks + fixed paths (`/b2b/v2/orders`, `/api/serialize`, …): baseline → **node-serialize** `_$$ND_FUNC$$_` timing (delta vs baseline, **replay-confirmed**) → **YAML billion-laughs** DoS (timing delta vs baseline, replay-confirmed); optional **Java** `application/x-java-serialized-object` magic bytes and **PHP** `O:8:"stdClass"` in JSON fields. Categories: **`rce-deserialization`**, **`deserialization-dos`**, **`deserialization-suspected`**.

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
**Next.js RSC / Flight deserialization** probe (CVE-2025-66478 class): fingerprint App Router → enumerate action hashes → Flight canary payloads. Sleep timing uses baseline POST delta only (**replay-confirmed**); no absolute slow-response timing without baseline. Category: **`nextjs-rsc-rce`**.

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

### Race Lab (multi-session race / TOCTOU)

Configurable bursts across **driver + peer sessions** with latency-compensated dispatch (measure RTT per session, stagger sends so requests arrive together), soft baseline, and unified findings (`tentative` / `likely` / `confirmed`).

**Quick scan vs Race Lab:** `POST /api/security/race-condition-scan` auto-discovers single-use POSTs from traffic and fires one hammer burst on the **driver** session. Race Lab is for **explicit request lists**, **peer identities**, and **Hammer / Spike / Sequential / Random** parameter presets (built-ins are presets only — all knobs remain editable).

**Peers (required for multi-identity races):** Register another Trowser instance with `POST /api/peer/register` (`name`, `baseUrl` on localhost, optional `apiKey`) before the run. Authenticate each instance separately if needed. With `ensurePeerOrigin: true` (default), peers are navigated to the target origin when their session is used. In each request, set `session` to `driver`, a registered **peer name**, or **`all-peers`** (default) to expand one row into **driver + every registered peer** for sync, baseline, and bursts.

**Request roles:** `observe` (default) — load or idempotent traffic; duplicate-action race findings are **not** emitted. `mutate` — single-use or state-changing actions (coupons, checkout, votes); use when duplicate **2xx** acceptance would be a bug. `check` — TOCTOU validation reads (check/use interference analysis).

### GET /api/race-lab/profiles
Lists built-in presets (`Hammer`, `Spike`, `Sequential`, `Random`) plus user-saved profiles from `%APPDATA%\\Trowser\\race-lab-profiles.json`.

### POST /api/race-lab/profiles
Save a user profile (`name`, `requests[]`, `parameters`). Built-in names cannot be overwritten.

### DELETE /api/race-lab/profiles/{name}
Delete a user profile (built-ins rejected).

### POST /api/race-lab/profiles/export
Body: optional `names[]`. Returns `{ format, json }` export payload.

### POST /api/race-lab/profiles/import
Body: `json` (export payload). Merges imported user profiles.

### POST /api/race-lab/synchronize
Body: **`profile`** `{ name, requests[], parameters }` **or** the same fields at the **top level** (`requests[]`, optional `parameters`). Returns `medianRttMs` and `dispatchOffsetMs` per session (after `all-peers` expansion).

### POST /api/race-lab/baseline
Same body shape as synchronize. One sequential soft pass per expanded request. Returns `baseline[]` timeline entries.

### POST /api/race-lab/run
**Safety gate:** `"safetyMode": "active"`.

| Field | Default | Description |
|-------|---------|-------------|
| `profile` | — | `{ name, requests[], parameters }` — **or** pass `requests[]` / `parameters` at top level (equivalent) |
| `requests[]` | — | Each: `name`, `url`, `method`, optional `headers`, `body`, `session` (`all-peers` \| `driver` \| peer name), `role` (`observe` \| `mutate` \| `check`), optional `responsePattern` (.NET regex; empty = no check — applies to any role) |
| `parameters` | — | `mode` (`hammer` \| `spike` \| `sequential` \| `random` \| `custom`), `requestsPerBatch`, `delayPerRequestMs`, `delayBetweenBatchesMs`, `totalBatches`, `durationMs`, `randomizeOrder`, `jitterMs`, `timeoutMs`, `includeBrowserCookies` (default **`true`** — session cookies on driver **and** peer fetches; `false` is forwarded to each peer). Each timeline entry includes `identityUsed` (`driver/browser-session`, `peer-name/anonymous`, …) and `cookiesSent` (names only). |
| `runSync` | `true` | Latency compensation before burst |
| `runBaseline` | `true` | Soft baseline before burst |
| `ensurePeerOrigin` | `true` | Navigate peers to target origin when needed |
| `minConfidence` | `likely` | Filter findings (`tentative`, `likely`, `confirmed`) |
| `includeHygiene` | `false` | Include hygiene-tier findings |

**Minimal run example** (top-level fields; hammer burst on a health check from driver + all peers, observe only):

```json
{
  "safetyMode": "active",
  "runSync": true,
  "runBaseline": true,
  "requests": [
    {
      "name": "health",
      "url": "https://app.example/api/health",
      "method": "GET",
      "session": "all-peers",
      "role": "observe"
    }
  ],
  "parameters": {
    "mode": "hammer",
    "requestsPerBatch": 10,
    "totalBatches": 1,
    "includeBrowserCookies": true
  }
}
```

**Mutating POST example** (single session; set `role` to `mutate` when duplicate acceptance is the hypothesis):

```json
{
  "safetyMode": "active",
  "profile": {
    "name": "Hammer",
    "requests": [
      {
        "name": "redeem",
        "url": "https://app.example/api/redeem",
        "method": "POST",
        "body": "{\"code\":\"PROMO-ONE-TIME\"}",
        "session": "driver",
        "role": "mutate"
      }
    ],
    "parameters": {
      "mode": "hammer",
      "requestsPerBatch": 15,
      "totalBatches": 2
    }
  }
}
```

Optional: `POST /api/race-lab/synchronize` with the same `requests[]` to inspect RTT offsets before a long run. `GET /api/race-lab/profiles` lists Hammer/Spike/Sequential/Random parameter presets (requests are usually empty on built-ins).

**Response patterns:** When `responsePattern` is set on a request, each timeline entry records `responsePatternMatched` (and `responsePatternError` for invalid regex). Findings use category `response-pattern` (single-shot mismatch or inconsistent matches under concurrent burst — useful for thread-safety / TOCTOU readbacks).

**Response:** `SecurityScanResult` envelope (`findings[]` with `confidence`, `details.baseline`, `details.timeline`, `details.sync`). Identical mutate successes are suppressed when they carry no new side-effect id (idempotent replay). Request ids, trace ids, and timestamps do not count. A finding is reported when accepted mutate responses disagree on order/charge/payment/booking/invoice ids (or a `Location` path id), or when a `check` readback lists more of those ids than the sequential baseline. Mark the follow-up GET `role: "check"` when the create call itself returns a fixed body.

**MCP:** `browser_race_lab_profiles`, `browser_race_lab_synchronize`, `browser_race_lab_baseline`, `browser_race_lab_run`.

**GUI:** More options → **Race Lab…**

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
**OWASP LLM Top 10 application-layer red-team scan** — YAML probe corpus (**LLM01–03 + LLM05–07 + LLM09**; see `coverage` in response), plus optional **RAG/memory poison** (LLM04), **peer embedding isolation** (LLM08 via `peerBaseUrl`), **unbounded consumption** (LLM10), **WebMCP abuse**, and **indirect injection**. Integrated with **Red Team Whisper**. Runs via discovered **HTTP adapter** (`openai` / `simple` / `custom`) or **chat UI** (`llm-chat-interact` helper).

Includes **system-prompt extraction** probes (`llm07_secret_password`, `llm07_initial_instructions`, …) and **output-handling** probes; LLM05 probes in **chat-ui** mode also run a **DOM render check** for unsafe HTML (`<script>`, `onerror=`, etc.) — may fire with `matched: "dom-unsafe-render"`.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `mode` | `auto` | `auto` \| `http` \| `chat` — in `auto`, prefers **chat-ui** when a widget exists and best HTTP endpoint `confidence` &lt; 50; otherwise high-confidence HTTP (`body:llm-json-shape`) over path heuristics |
| `maxProbes` | `28` | Cap corpus probe count (`0` = adjacent scanners only) |
| `concurrency` | `2` | Parallel probes (HTTP mode only; chat-ui always runs sequentially to avoid DOM conflicts) |
| `timeoutMs` | `30000` | Per-request timeout |
| `probeDelayMs` | `1000` | Delay between probes in chat-ui mode (200–10000 ms). Helps avoid rate limits |
| `includeWebMcpAbuse` | `true` | Curated WebMCP tool argument fuzz after corpus |
| `includeIndirectInjection` | `false` | Upload doc with hidden instruction + summarize |
| `includeRagPoison` | `false` | LLM04 memory/RAG persistence (+ LLM08 if `peerBaseUrl` set) |
| `includeUnboundedConsumption` | `false` | LLM10 flood / oversized / max-output / tool-loop |
| `peerBaseUrl` | — | Peer Trowser base URL for cross-tenant embedding check |
| `peerApiKey` | — | Bearer key for peer |
| `registerWhisperHints` | `true` | Push findings to Red Team Whisper |
| `httpTarget` | — | `{ url, schema, model, headers, useBackendFetch, customBody, customResponseKey }` — `customBody` may be a **JSON object** or a **string** form/raw template; supports `{{PROMPT}}`, `{PROMPT}`, `§PROMPT§`, `{{MODEL}}` placeholders. **JSON templates are parse-then-substituted** (multiline/HTML-safe). Form-urlencoded bodies URL-encode values. When `Content-Type` is `application/x-www-form-urlencoded` (or `customBody` is a non-JSON string), the adapter sends form-urlencoded and refreshes common CSRF fields from the page/cookies. Discovered OpenAI-style `messages[]` bodies are inferred as single-turn `{{PROMPT}}` custom targets. |
| `chatTarget` | — | `{ inputSelector, submitSelector, responseSelector, waitAfterSubmitMs }` |
| `probeIds` / `categories` | — | Optional filters; unknown IDs/categories returned in `warnings[]`. Alias: `LLM02_Insecure_Output_Handling` → `LLM05_Improper_Output_Handling`; legacy `LLM04_Model_Denial_of_Service` → `LLM10_Unbounded_Consumption` |

**Chat-UI response capture** prefers **new** assistant content: DOM nodes whose text was not in the pre-submit baseline, then **HTTP network/SSE** response bodies and **WebSocket** frames for chat-like POSTs. Stale prior-turn bubbles and user echoes are rejected (`responseChanged` stays false / warning set). Typing indicators are waited out.

**Typing indicator filtering:** both JS capture and C# polling detect typing indicators (`[typing...]`, `thinking...`, `loading...`, animated dots, `class="typing"`, `aria-busy="true"`, etc.) and wait through them. The scanner only accepts stable non-typing text. If the deadline expires with only a typing indicator captured, the result is treated as empty (not falsely reported as a real response).

**Dual-channel WebSocket capture:** for pages with active WebSocket connections, frame state is snapshot before each probe submission. If DOM capture fails or returns a typing indicator, new received JSON frames are checked for content fields (`content`, `message`, `response`, …). WebSocket responses appear with `responseSelector: "websocket"`. Supports nested message formats (OpenAI `choices[].message.content`, flat `{ content: "..." }`, etc.).

**Chat-UI resilience:** probes run sequentially; page state is verified before each probe (re-navigates if the page was lost). Rate-limit responses ("too fast", "rate limit", "please wait", …) trigger a 12s back-off + retry.

Response includes `confidence` per probe (`high` | `medium` | `low` | `refused` | **`inconclusive`**). Empty or stale chat responses, HTTP **4xx/5xx**, and HTML error/CSRF pages are **`inconclusive`**, not confident "not fired". Refusal/echo detection avoids firing when the model quotes the probe token without complying. With `verbose: true`, chat-ui probes also populate `verboseTrace` (DOM submit + related network POSTs).

**MCP:** `browser_security_llm_redteam_scan`.

### GET /api/security/llm-redteam-probes
**Probe catalog** — lists all probe IDs, category names, and `coverage` metadata (use for `probeIds` / `categories` filters). Gate-free. **MCP:** `browser_security_llm_redteam_probes`.

### GET or POST /api/security/llm-endpoint-discover
**LLM surface discovery** — network log chat/completion APIs (including **SSE** `text/event-stream` and form-urlencoded prompt fields), **WebSocket connections** (JSON message pattern analysis for `content`/`message`/`response` keys, user/role indicators, multi-turn patterns), DOM chat widgets, WebMCP tool count, copilot iframes. Sets `botGateDetected` when reCAPTCHA/hCaptcha/Turnstile-like widgets are present. WebSocket endpoints appear with `source: "websocket"`, `method: "WS"`. Dedupes by URL. Endpoints include `confidence` (0–100) and `isSse`. Filters third-party analytics/tracking domains (HubSpot, hsforms, GA, …), static assets (`.gif`, …), and non-JSON/image responses from weak path matches. DOM chat widget discovery detects off-screen inputs (below-fold chat inputs still discovered, with lower confidence). Response area detection probes for table/list/container structure near the chat input; default response selectors exclude heading/label false hits. Updates Red Team Whisper `llmSurface`.

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

**Response:** `rateLimitRespected`, `http429Responses`, `skippedDueTo429[]`, `backoffEvents`, `findings[]`.

- **`rateLimitRespected`** — `true` only when this run **honored HTTP 429** with Retry-After backoff (`respectRateLimits: true`). **`false` does not mean “the target has no rate limit”** — it usually means no 429 was seen during probing.
- **`http429Responses`** — count of HTTP **429** responses observed (any attempt). Use with `findings[]` (`missing-rate-limit` vs `rate-limit-present`).
- **`missing-rate-limit`** findings are emitted only for **sensitive** traffic classes (login, OTP, coupon, search, export, write API) — not for generic static document GETs.

**MCP:** `browser_security_rate_limit_audit`.

### POST /api/security/redos-scan
**ReDoS timing oracle** — evil-regex payloads per injectable search/filter/email parameter (max 3, sequential). Initial slow sample is **replay-confirmed** against a **same-length benign** control string. Category: **`redos-suspected`**.

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
**Body-size limit probe** — escalating tiers 1 KB → 64 KB → 256 KB → 1 MB (one request per tier) on **POST/PUT/PATCH** endpoints only (GET/HEAD are skipped — many servers ignore request bodies on GET). Categories: **`body-size-unbounded`** (2xx at 1 MB without 413), **`body-size-no-413`** (2xx at intermediate tiers), **`body-size-limit-present`** (HTTP 413). Endpoints that reject all tiers with 4xx (e.g. 400 CSRF, 405 method) are skipped.

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

### POST /api/security/costly-operations
**Single-request cost risk scan** — analyzes captured traffic and optional DOM for operations that can be expensive on one or a few requests (rate limits may not help). Passive by default (zero extra HTTP). Categories include **`costly-large-response`**, **`costly-missing-pagination`**, **`costly-page-size-honored`**, **`costly-unbounded-page`**, **`costly-heavy-route`**, **`costly-slow-sync`**, **`costly-bulk-input`**, **`costly-expansion`**, **`costly-upload-surface`**, **`costly-n-plus-one`**, plus compose-links (`relatedProbe`: `graphql-analyze`, `llm-redteam-scan`, `ssrf-scan`, `redos-scan`, `file-upload-scan`, `websocket-audit`).

List findings weigh response bytes, not row count alone. A 50-row lookup of a few hundred bytes is not reported. Missing paging is medium unless the list is about 100 rows or the body is at least 32 KB. N+1 requires distinct resource URLs (repeated config fetches and Socket.IO polling are ignored). Nested-payload flags base64-like or `data:` JSON fields, not long prose or HTML. OpenAPI leads use the operation method and resolved operation URL; the spec document stays in `evidence`. Traffic-backed findings include **`networkEntryId`** (matches `id` on `GET /api/network` entries) so you can jump straight to the captured request/response.

**Safety:** Default `"safetyMode": "passive"`. An unknown `safetyMode` or check id returns **400** (it is not coerced). Optional bounded confirms (`confirm-page-size`, `confirm-image-edge`, `confirm-multi-id`) require `safe`+ (GET) or `active` for state-changing replays; list them in `checks`. `confirm-page-size` steps an existing page-size parameter (`limit`, `per_page`, …) up to 100 and reports growth as `costly-page-size-honored` — not proof there is no higher cap. `skip` / `offset` / `page` are not page size. On an unpaged list GET it also tries `limit=50`. `confirm-image-edge` runs only when the URL already has a dimension parameter. `urls` scopes network entries and DOM file-input leads.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `passive` | `passive` \| `safe` \| `active` \| `aggressive`. Unknown values return 400 |
| `checks` | all passive | Check ids; add confirm-* ids for bounded probes. Unknown ids return 400 |
| `maxCandidates` | `24` | Max endpoints per rule |
| `timeoutMs` | `15000` | Per confirm request timeout |
| `maxResponseBytes` | `2097152` | Abort confirm if response body exceeds cap |
| `slowThresholdMs` | `3000` | Flag slow sync API calls |
| `includeSpaDom` | `true` | File inputs from interactive DOM |
| `includeBrowserCookies` | `true` | Session cookies on confirms |
| `respectRateLimits` | `true` | Backoff on HTTP 429 |
| `registerChainFindings` | `true` | Register observed/confirmed for chain-analyze |
| `urls` | — | Optional URL scope filter (network entries and DOM file-input leads) |
| `includeSpecsFromNetwork` | `true` | Parse OpenAPI / GraphQL introspection from captured responses (same origin) |
| `specUrls` | — | Only analyze these spec URLs from the network log (e.g. `/openapi.json`) |

**Passive check ids (default all):** `large-response`, `pagination`, `heavy-route`, `slow-sync`, `bulk-input`, `expansion`, `upload-surface`, `traffic-shape`, `nested-payload`, `recipient-fanout`, `date-range`, `filter-depth`, `spec-limits`, plus `compose-*` links.

**MCP:** `browser_security_costly_operations`.

### POST /api/security/swaggering
**Swaggering** — discover OpenAPI/Swagger (traffic + well-known paths), build an operation catalog, run **session-authenticated** probes against documented routes (uses the browser cookie jar — not a Postman-style client). Phases: spec discovery, API inventory (documented/shadow), passive spec cost hints, per-operation smoke (5xx, verbose errors, slow responses, auth delta, forced-error/missing-field on JSON bodies, cost edges), shadow path GETs, then **auto-scan** on the merged attack surface when `safetyMode` allows writes.

Alias: `POST /api/security/openapi-smoke` (same handler).

**Positioning:** Log in in the WebView first; Swaggering exercises the contract with that session (SSO, HttpOnly cookies, captured CSRF/API headers when traffic matches).

**Safety:** Default `"safetyMode": "active"`. `passive` = discover + spec-limits only (no operation HTTP). `safe` = GET/HEAD/OPTIONS smoke only. `aggressive` = stronger cost edges; set `includeDeleteMethods: true` explicitly for DELETE. **Blocked in `--safe` mode** when probes would send HTTP.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `active` | `passive` \| `safe` \| `active` \| `aggressive` |
| `depth` | `thorough` | `quick` (~2 min) \| `standard` (~8 min) \| `thorough` (~20 min wall clock) |
| `maxStepSeconds` | from depth | Override time budget (thorough default 1200) |
| `specUrls` | — | Explicit OpenAPI document URLs |
| `includeSpecsFromNetwork` | `true` | Parse OpenAPI from captured responses |
| `includeOpenApiProbes` | `true` | GET-probe `/openapi.json`, `/api/v3/openapi.json`, `/v2/swagger.json`, `/v3/api-docs`, etc. Misses (404/410) are not warnings |
| `pathPrefix` | — | Limit to paths under prefix (e.g. `/api/v1`) |
| `includeDeprecated` | `false` | Include deprecated operations |
| `includeDeleteMethods` | `false` | Include DELETE in operation list |
| `timeoutMs` | `12000` | Per-request timeout |
| `includeBrowserCookies` | `true` | Session cookies on probes |
| `registerChainFindings` | `true` | Register `swaggering-*` categories for chain-analyze |
| `includeCostlySpecLimits` | `true` | Passive OpenAPI cost/limit hints |

**Finding categories:** `swaggering-server-error`, `swaggering-verbose-error`, `swaggering-slow`, `swaggering-auth-anomaly`, `swaggering-shadow-exposed`, `swaggering-injection-hint`, `swaggering-sensitive-data` (JSON field names such as `password` / `apiKey`; values are not echoed).

**Response:** `operationsInCatalog`, `operations[]` (`method`, `path`, `operationId`, `requiresSecurity`, `outcome` = `probed` | `skipped` | `not-probed` | `not-reached`, smoke `status`, `url`, `skipReason`), `coverage` (`probed`, `skipped`, `notProbed`, `notReached`, `http2xx`, `http4xx`, `http5xx`), `specSources`, `phasesCompleted`, `warnings` (401/403 and real parse failures — not ordinary 404 probes), `inventory` counts, `shadowPaths[]` (spec documents and Swagger UI assets are omitted), `findings[]` (includes `evidence`, a short response excerpt; secret values are not included), `costlyFindings[]` (from the loaded spec, not only the browser network log), optional `autoScan` summary scoped to the catalog plus observed traffic (generic scaffold paths such as `/rest/products/search` are not probed), `partial` / `budgetExhausted`. `requestsSent` counts Swaggering probes only. The summary `message` counts swaggering findings, spec-cost hints, and auto-scan findings together. A repeated 500 on a later variant of the same operation is collapsed into one finding.

**MCP:** `browser_security_swaggering`.

### POST /api/security/workflow-skip-scan
**Multi-step workflow bypass** — infers late-stage POST endpoints from traffic (confirm, complete, submit, redeem, …). Replays the **captured** body first (same browser session — may succeed on legitimately replayable flows), then tries **`{}`** without CSRF injection. Category: **`workflow-step-skip`** (findings); captured-body 2xx → **`observations[]`** (`workflow-replay-accepted`, info).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `maxCandidates` | `8` | Max late-stage endpoints |
| `timeoutMs` | `10000` | Per-request timeout |
| `tryMinimalBody` | `true` | Also try `{}` (minimal-body acceptance → **medium** finding when not gated) |
| `includeBrowserCookies` | `true` | Send session cookies |
| `urls` | — | Optional explicit POST URLs (bypass late-stage keyword filter) |

**Response:** `properlyGated[]` includes `gateType`: `csrf-validation` or `business-rejection`. Empty 2xx bodies are **not** treated as acceptance. CSRF tokens are extracted via direct DOM query (`input[type=hidden][name=csrf]`), not `interactiveElements`.

**MCP:** `browser_security_workflow_skip_scan`.

### POST /api/security/cmd-canary
**Command injection / RCE indicator** canaries on injectable string parameters. **Tier A:** error-based (`\`id\``, `$(id)`, `;id`, `|id`); **Tier B:** SSTI arithmetic; **Tier D:** OOB callback (`includeCallback: true`); **Tier E:** timing (`includeTiming: true`, confirmed replay). Categories: **`command-injection`**, **`ssti-confirmed`**, **`rce-indicator`** (timing only); **`callback-browser-hit`**, **`callback-reflection`** (**info**, browser/client signals — not server RCE).

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | Optional template with **`§INJECT§`** marker |
| `paramName` | — | Parameter name for explicit template |
| `maxCandidates` | `10` | Max injection points from network log |
| `includeSstiTier` | `true` | Include SSTI arithmetic tier |
| `includeCallback` | `false` | Browser network log watches `/probe-cmd-*` callback URLs only |
| `includeTiming` | `false` | Timing tier (sleep payloads; requires confirmed second slow sample) |
| `timingThresholdMs` | `3500` | Min delta vs baseline for timing finding |
| `callbackWaitMs` | `2000` | Wait after probes for callback hits |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `message`, `candidatesProbed`, `payloadsSent`, `findings[]` (category, tier, paramName, payload, indicator, detail). **`command-injection`** with weak indicators (`Linux`, `/bin/` in errors) is **medium**; **`uid=`** / **`gid=`** / Windows IP remain **critical**.

Explicit probes need a marker in the request, not a bare parameter name. `{{INJECT}}` and `§INJECT§` are equivalent:

```json
{ "safetyMode": "active", "request": { "url": "https://target.example/api/exec?command={{INJECT}}" } }
```

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

### GET /api/security/nuclei-templates
Inventory the runnable nuclei templates (embedded subset and/or a user `templatesDir`) **without scanning**, so you can pick applicable templates before running probes.

| Query param | Default | Description |
|-------------|---------|-------------|
| `templatesDir` | — | Optional directory of user `*.yaml`/`*.yml` templates to include (same fallbacks as the scan endpoint) |
| `includeBuiltinTemplates` | `true` | Set `false` to list only your `templatesDir` templates |

**Response:** `count`, `templates[]` (`id`, `name`, `severity`, `tags`, `methods`, `source` = `embedded`\|`user`), `tags[]` (tag catalog with `count`), `skippedTemplates[]` (`id`, `reason`, `source` for unsupported/unparseable templates), `compatibilitySummary` (`runnable`, `skipped`, `filesScanned`, `skippedByReason` map).

**MCP:** `browser_security_nuclei_templates`. **Scripting:** `ListNucleiTemplates(templatesDir, includeBuiltinTemplates)`.

### POST /api/security/nuclei-scan
Native runner over a **curated embedded subset** of [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT), plus **your own templates**. Supports **HTTP** templates with matchers `status` / `word` / `regex` / `header` only — not the full Nuclei DSL (no dns/tcp/headless/code/workflows/raw, no multi-field payload attacks). URL placeholders: `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`, `{{Scheme}}`, `{{Path}}`, `{{File}}`, plus **`payloads.paths`** expansion for `{{paths}}` (max 128 paths per block; optional `stop-at-first-match`). Probes use the **browser cookie jar** by default (`includeBrowserCookies: true`). Embedded templates ship under `Resources/nuclei/`. **Not a Nuclei replacement** — use `GET /api/security/nuclei-templates` for inventory + skip reasons before scanning a downloaded pack.

**Safety gate:** `"safetyMode": "safe"` is enough when all selected templates use GET/HEAD/OPTIONS. Write-verb templates require `"safetyMode": "active"`. `dryRun: true` needs no safety mode (it sends no HTTP). **Blocked in `--safe` CLI mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `"safe"` | `"safe"` (GET/HEAD-only subset) or `"active"` / `"aggressive"` (needed for write-verb templates). Omitting defaults to `safe`; `passive` is rejected (except with `dryRun`). |
| `targetUrl` | current page | Base URL for `{{BaseURL}}` / `{{RootURL}}` |
| `targetUrls` | — | Optional list of base URLs to scan; each selected template runs against every URL. Accepts a JSON array or a comma-separated string. Merged with `targetUrl` and deduped. |
| `tags` | — | Optional tag filter — a JSON array (`["exposure","misconfig"]`) **or** a comma-separated string (`"exposure,misconfig"`). Runs templates matching any listed tag. |
| `severity` | — | Optional **minimum** severity filter (`info`\|`low`\|`medium`\|`high`\|`critical`) — includes that severity and higher. Alias: `minSeverity` (both accepted; `minSeverity` wins if both set). |
| `maxTemplates` | `50` | Cap on templates to run (after tag/severity filtering) |
| `timeoutMs` | `10000` | Per-request timeout |
| `followRedirects` | `false` | Follow HTTP redirects. **Default false** so redirect/`Location` matchers (e.g. open-redirect templates asserting `302` + `Location`) can match the intermediate response. |
| `templatesDir` | — | Optional directory of user `*.yaml` / `*.yml` templates to load (recursively) in addition to the embedded subset. Falls back to `%TROWSER_NUCLEI_TEMPLATES%` or a `nuclei-templates/` folder beside the exe when unset. User templates go through the same parser/limitations and are filtered by `tags`/`severity`. |
| `includeBuiltinTemplates` | `true` | Set `false` to run **only** your `templatesDir` templates (skip the embedded subset). |
| `dryRun` | `false` | Resolve/select templates and return `selectedTemplateIds` **without sending any HTTP** (works in any safety mode). |
| `verboseTemplateTrace` | `false` | Return `templateTrace[]` with per-template `url`, `method`, `statusCode`, `matched`, `requested`. |
| `registerChainFindings` | `true` | When `true`, register matches as chain findings (`Source=nuclei`, category `nuclei-match`) |
| `includeBrowserCookies` | `true` | When `true`, attach WebView2 cookies (HttpOnly included) to each probe via server-side fetch. |

**Response:** `targetUrl` (first URL), `targetUrls` (all scanned URLs), `dryRun`, `includeBrowserCookies`, `estimatedHttpRequests` (planned or actual request count after path/payload expansion × targets), `compatibilitySummary` (same shape as the templates inventory), `templatesLoaded` (total candidate pool — embedded + user), `templatesSelected` (after tag/severity/max filtering), `templatesRun` / `httpRequests` (individual HTTP requests sent — one per template path per URL), `templatesFilteredOut` (alias: `templatesSkipped` — loaded but excluded by filters), `selectedTemplateIds[]` (always present), `matchedTemplateIds[]` (templates that produced a finding), `skippedTemplates[]` (`id`, `reason`, `source` — templates that could **not** be run due to DSL limits/parse errors), `findingCount`, `findings[]`, `templateTrace[]` (when requested), `summary[]`, `report`. Returns **400** when no templates match the filters.

Each `findings[]` entry uses stable common fields shared across scanners — `title` (= template name), `description` (= detail), `severity`, `url` — alongside `templateId`, `templateName`, `category`, `method`, `statusCode`, `detail`, `tags`.

> **Note:** nuclei uses a dedicated `HttpClient` outside the generic request-trace chokepoint, so a `verbose` scan's `verboseTrace.requestCount` will **not** include nuclei probes — use `httpRequests` (or `verboseTemplateTrace`) in this response for the count.

> **Custom templates:** point `templatesDir` at a folder of Nuclei HTTP YAML (or drop files in `nuclei-templates/` beside the exe). Unsupported DSL (dns/raw/dsl matchers/multi-key payloads/attack modes) is skipped **with a reason** — see `skippedTemplates[]` and `compatibilitySummary`. Use `dryRun: true` to preview selection and `estimatedHttpRequests`. To scan many hosts, pass `targetUrls`.

**Embedded templates (Trowser-authored YAML in `Resources/nuclei/`, not GitHub filenames):** modern exposure sweeps — `env-paths-exposure` (`.env` path list at **`{{RootURL}}`**), `swagger-api-paths`, `javascript-env-exposure`, `frontend-config-json`, `graphql-ide-exposure`, `git-config-exposure`, `aws-credentials-exposure`, Spring `actuator-*`, `robots-txt`, `security-txt`; legacy/stack-specific (tag **`legacy`**) — `phpinfo-exposure`, `wordpress-login`, `ds-store-exposure`, `htaccess-exposure`, `nginx-conf-exposure`, `web-config-exposure`, `apache-server-status`, `docker-registry-api`. Origin-level probes use **`{{RootURL}}`** so deep `targetUrl` paths do not miss `.env`/swagger at the host root. Filter with **`tags`**: e.g. `"exposure"` without `legacy` for SPA-focused runs. Call `GET /api/security/nuclei-templates` for the live list (id/severity/tags/methods).

**MCP:** `browser_security_nuclei_scan`, `browser_security_nuclei_templates`. **Quicktest:** `Security/3 NucleiScan.csx`. **Scripting:** `RunNucleiScan` / `AssertNucleiClean` / `PrintNucleiReport` / `ListNucleiTemplates` (scan methods accept `targetUrls`, `templatesDir`, `includeBuiltinTemplates`, `followRedirects`, `dryRun`, `verboseTemplateTrace`, `includeBrowserCookies`).

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
| `algorithm` | — | Top-level alg override (for example `none`). Written to `header.alg`. `none` also sets `stripSignature` unless you pass `stripSignature` explicitly |
| `modifications` | — | Optional object: `header`, `payload`, `header.alg`, `payload.role`, … `modifications.header.alg` is the same knob as `algorithm` (top-level `algorithm` wins if both are set) |
| `stripSignature` | `false` | Clear signature segment (typical with unsigned / `none` flows). Implied when `algorithm` is `none` |

```json
{
  "safetyMode": "active",
  "baseToken": "<jwt>",
  "algorithm": "none",
  "modifications": { "payload": { "user": "admin" } }
}
```

Equivalent: `"modifications": { "header": { "alg": "none" }, "payload": { "user": "admin" } }` and `"stripSignature": true`. A payload-only `modifications` object does not change `alg`.

**MCP:** `browser_security_jwt_forge`.

### POST /api/security/jwt-acceptance-sweep
Cookie-isolated sweep for **missing authentication** and **JWT alg:none acceptance** (anonymous GET vs forged alg:none). Prefer explicit `endpoints[]` for focused proofs; otherwise uses attack-surface candidates from the network log (browse first).

`MISSING_AUTH` requires response body to look like **authenticated/sensitive content** — HTTP 200 login pages (password fields, sign-in text) are **not** flagged (avoids false positives on Java/JSP apps that redirect to login with 200).

When the token comes from (or `cookieName` names) a cookie JWT, each gated endpoint is probed with both `Authorization: Bearer` and `Cookie: <name>=`.

A JWT in `localStorage` / `sessionStorage` (or any other `jwt-analyze` source) is used in full as `baseToken` for the forged alg:none variants. A session cookie on the same site does **not** skip those tests — cookie auth and JWT auth are independent. Network-log candidates default to the current page host; well-known third-party/CDN hosts and static image/script/font responses are not scored as `MISSING_AUTH`. alg:none is sent on anonymous **2xx and 4xx** responses, not only 401/403.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_jwt_acceptance_sweep`.

| Field | Default | Description |
|-------|---------|-------------|
| `token` / `baseToken` | — | Explicit JWT or Bearer token (alg:none accepted as-is) |
| `endpoints` | — | Absolute URLs (strings or `{ url }`) to probe. When non-empty, **only** these are tested unless `includeNetworkLog` is true |
| `includeNetworkLog` | auto | Default `false` when `endpoints` is set, else `true`. Controls attack-surface candidates from the network log |
| `cookieName` | auto | Cookie header name for cookie-transport probes (e.g. `_dct`). Inferred from cookie JWT sources when possible |
| `host` | — | Limit network-log candidates to host |
| `maxEndpoints` | 15 | Cap endpoints tested |
| `verbose` | false | Include `jwtPayloadUsed` / transport detail per row |
| `includeUnauthenticatedOnly` | false | Skip JWT tests when no token |
| `includeAlgVariants` | true | Test case/whitespace/missing alg variants when canonical none rejected |

**Response:** `rows[]` (`NO_ISSUE`, `MISSING_AUTH`, `JWT_ALG_NONE_ACCEPTED`, `JWT_ALG_VARIANT_ACCEPTED`; each may include `transport`: `bearer`\|`cookie`\|`anon`), `summary[]`, `endpointsTested`, `jwtSource`, `cookieName`, `includedNetworkLog`, `explicitEndpoints`, `authContext`.

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

**Response:** `ids[]` with `type`, `paramName`, `source` (`query-param`, `network-path`, `network-json`, `dom`), `contextUrl` (request URL, not data URIs), `sequential` flag; `suggestedBoundaryTests[]` for IDOR boundary probes.

Path-segment ids from same-origin **2xx** API calls are preferred over values parsed out of an OpenAPI document. A single numeric path id (`/api/users/id/1`) always produces a `suggestedBoundaryTests` entry (`/api/users/id/{id}`). Spec example values, `operationId` strings, and third-party hosts (maps, CDNs) are not harvested as object ids.

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
Detects **session fixation** — captures **all** cookies before login, authenticates, flags unchanged **session-like** cookies (excludes CSRF/analytics names; skips unchanged cookies when login issued a new session cookie). Category: **`session-fixation`**. Chain-prove: `session-fixation-proof`.

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

Uses same form-login enrichment as session-fixation-scan. When **`loginUrl`** is set, Trowser **navigates to that URL once** to read the real login form field names (including when the app runs on a **different origin** than the lesson page), then **restores the prior document URL** — so HTML form apps are not mis-probed as JSON. Explicit **`contentType: application/x-www-form-urlencoded`** forces form encoding even for `/login` paths. Message heuristics include common “wrong password” / “no account” wording (not only “invalid credentials”). Gracefully handles missing/empty `Content-Type` on login requests.

**Response:** `message`, `elapsedMs` (whole scan), `loginDifferentialMs`, `findings[]`, `summary[]`, `warnings[]` (e.g. JSON body with form Content-Type, or identical valid/invalid responses — probe may be mis-encoded).

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
**Logout invalidation** — perform logout, replay protected URL with pre-logout cookie; flags **`SESSION_STILL_VALID`** only when the **logout step succeeded** (2xx/3xx — not 404/405). If logout did not run, returns **`logoutPerformed: false`** and **no** session finding. **Intentional logout URLs** (e.g. `/logout`) are executed by the probe — generic scanners still skip session-termination paths to avoid accidental sign-out. Detects invalidation when post-logout response is a **login page** (HTTP 200 + password field), not only 401/403. Browse while logged in first.

Auto-detect prefers **POST logout forms** on the page, **Sign Off/Logout** links, **network log** (method + body), then path hints (`/logout` before stack-specific hints like `/logout.jsp`). **`logoutMethod`** is applied to the discovered URL even when **`logoutUrl`** is omitted. An inferred **GET** that returns **405** is retried once as **POST**. Pass **`logoutBody`** for POST-only logout routes; a body without a method upgrades an inferred GET to POST.

**Safety gate:** `"safetyMode": "active"`. **MCP:** `browser_security_logout_invalidation_probe`.

| Field | Default | Description |
|-------|---------|-------------|
| `logoutUrl` | auto | Logout URL |
| `logoutMethod` | auto / DOM | `GET`, `POST`, … Applied even when the URL is discovered automatically |
| `logoutBody` | auto / DOM | Form body for POST logout |
| `logoutContentType` | auto | e.g. `application/x-www-form-urlencoded` |
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
Mass-assignment probe (OWASP API / broken object property level authorization) for a **JSON object** or an **`application/x-www-form-urlencoded`** body. Sends a baseline request, then **one request per candidate field** with an extra property merged in (`role`→`"admin"`, numeric `UserId`→`2`, `balance`→`999999.99`, etc.). **Candidate fields** = optional **`privilegedFields`** plus keys from the request, a JSON response, or HTML `name` attributes that match built-in patterns (`role`, `UserId`, `balance`, …). **`valueReflected`** means that field echoed the injected value (JSON property, form pair, or input value — not a short token such as `true` or `2` somewhere in the HTML). **`valuePersisted`** is set only when **`verifyPersistence`** is true and a follow-up fetch shows the value **and the baseline fetch did not**. Echo without a state change is not reported as persisted.

**Safety gate:** `"safetyMode": "active"`. **Blocked in safe mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"`. (`confirmBackend: true` accepted as legacy alias) |
| `request` | — | **`{ url, method?, headers?, json? \| body? }`** — JSON object or `application/x-www-form-urlencoded` (required). Content-Type is taken from `headers` when set, otherwise inferred |
| `privilegedFields` | *(optional)* | Extra field names to inject (e.g. `["role","isAdmin","UserId"]`) |
| `verifyPersistence` | `false` | Re-fetch resource after inject; set **`valuePersisted`** when field sticks |
| `verifyFetchUrl` | same as request.url | GET (or custom method) URL for persistence check |
| `verifyFetchMethod` | `GET` | Method for persistence check |
| `timeoutMs` | `15000` | Per-request timeout |

**Response:** `baselineStatus`, `baselineBodySample`, `bodyKind` (`json` or `form`), `fieldsTested[]`, `summary[]`, `probes[]` (field, injectedValue, status, valueReflected, **valuePersisted**, **evidence**, verifyFetchUrl, bodySnippet).

**MCP:** `browser_security_mass_assignment_scan`.

### POST /api/security/mass-assignment-patch
**PATCH/PUT self-promote** mass-assignment probe (OWASP WSTG-INPV-20 / API mass-assignment): discovers profile update endpoints from traffic, injects privileged fields (`role`, `isAdmin`, `balance`, …), then **verifies persistence** via GET `/api/users/me` (or discovered me URL). Reflection-only hits are at most medium.

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

**Response:** `rows[]` (every probe), `findings[]` (only `result: "bfla"`), `summary[]`. Per-row `severity` follows `result`: `denied`, `spa-shell`, and `error-page` are `info`; a genuine 2xx JSON write is `high`, or `critical` when anonymous is denied and the session is accepted. `findings[]` is the finding list.

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
| `payloadProfile` | `"small"` | Payload corpus: **`small`** (built-in curated catalogs — default) or **`big`** (merge SecLists / PayloadsAllTheThings subsets from `corpora/` or `%TROWSER_CORPORA%`, still hard-capped). Orthogonal to `scanDepth` / `safetyMode`. |
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
| `includeCacheMap` | `true` | Run cache-map indication (identify + busted key mapping; not live-key pollution) |
| `includeCacheDeception` | `true` | Run cache deception when session cookies exist |
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

**Response:** `warnings[]`, **`scanDepth`** (applied profile: `quick` | `standard` | `thorough`), **`payloadProfile`** (applied: `small` | `big`), **`corporaAvailable`** (true when external corpora are present — if `false` while `payloadProfile=big`, the run silently fell back to built-in `small` catalogs), **`maxStepSeconds`** (applied budget), **`budgetExhausted`** / **`partial`** (true when the step budget cut the run short — findings already collected are still returned), `endpointsDiscovered`, `endpointsScanned`, `scannersRun[]`, `scannersSkipped[]`, `findingsCount`, `findings[]` (scanner, severity, endpoint, method, title, detail, optional `occurrences` when deduped, optional `nextActions[]` verify-workflow stubs), `attackSurfaceSummary`, `errors[]`, `elapsedMs`.

**MCP:** `browser_security_auto_scan`.

### POST /api/security/secrets-harvest
Unified **secret/credential harvesting** across all browser sources in one call: **JS bundles** (hardcoded credentials, API keys, internal URLs via `js-audit`), **cookies & storage** (JWT tokens, auth tokens, PII via `jwt-analyze` + `storage` audit), **network responses** (leaked credentials, bearer tokens, password hashes in response bodies), **network request headers** (Bearer tokens, API keys in `Authorization`, `X-Api-Key`, `X-Auth-Token` headers — category `api-key-in-request`), **visible page text** (debug output, exposed secrets), and **source maps** (exposed `.map` files, debug mode indicators). Returns **deduplicated**, **severity-prioritized** findings. Includes **false positive suppression** for known library patterns (e.g. lodash FP alias mappings).

**Safety gate:** `"safetyMode": "safe"` runs the **passive** sources (cookies/storage, captured network log, page text/HTML comments). `"safetyMode": "active"` additionally **fetches** JS bundles and source maps (new outbound requests). **Blocked in `--safe` CLI mode.**

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `"safe"` | `"safe"` (passive sources) or `"active"`/`"aggressive"` (also fetch JS bundles + source maps). (`confirmBackend: true` accepted as legacy alias for active.) |
| `includeJsBundles` | `true` (active only) | Scan JS assets for hardcoded secrets — **only runs under active** (needs outbound fetch); forced off under safe. URLs come from **`script[src]` on the current page** plus **same-origin `ResourceType: Script` rows** from the network log (covers extensionless `/app` scripts and other paths without `.js` in the URL when the log already captured them). |
| `includeCookiesAndStorage` | `true` | Analyze cookies, localStorage, sessionStorage for tokens/PII (passive) |
| `includeNetworkResponses` | `true` | Scan captured network response bodies for credential exposure (passive) |
| `includePageText` | `true` | Scan visible page text for secrets/debug output (passive) |
| `includeSourceMaps` | `true` (active only) | Check for exposed source maps and debug mode — **only runs under active** (needs outbound fetch); forced off under safe. |
| `maxJsScripts` | `20` | Max JS scripts to fetch and scan |
| `maxNetworkResponses` | `100` | Max network response bodies to scan |
| `maxBytesPerFile` | `1048576` | Max bytes read per JS bundle |
| `includeHtmlComments` | `true` | Scan HTML comments in page source (passive) |
| `timeoutMs` | `30000` | Timeout for JS bundle fetches |

**Response:** `url`, `totalFindings`, `filteredNoise` (findings dropped by hard suppress and per-script comment caps), `findings[]` (source, category, severity, location, description, snippet), `warnings[]` (e.g. large-bundle truncation — not counted as secrets), `summary` (critical, high, medium, low, info, bySource, byCategory), `sourcesScanned[]`, `passiveOnly` (true when JS/source-map fetching was skipped under safe), `errors[]`, `elapsedMs`. Detects emails, Luhn-valid credit cards, PEM private keys, JWTs, API keys, and comment-embedded secrets.

**MCP:** `browser_security_secrets_harvest`.

### POST /api/security/oidc-analyze
**OIDC session dossier, optional provider metadata, and relying-party JWT checks.** Tries `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`. **Many issuers omit discovery** — the call still returns **`dossier`**, **`session`**, and **`rpTokenFindings`** when the browser captured a login. When discovery exists, provider checks include:

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

**Auto-detection** (when `issuer` is omitted): scans the network log for `.well-known/openid-configuration` (and `oauth-authorization-server`) fetches, JWT `iss` in Bearer tokens, cookie values, and JSON bodies, and authorize URLs with `client_id` (`/authorize`, `/protocol/openid-connect/auth`, `/oauth2/v2.0/authorize`, `/o/oauth2/v2/auth`, and the other standard paths).

**Reverse-proxy / BFF logins** never put the issuer in the browser. The response still includes **`session`**: `binding` `bff-proxy` or `claims-only`, login UI path (query stripped), claim type names (not values), cookie flags, and what cannot be tested until you pass `issuer`. Do not use the login UI host as the issuer.

| Field | Default | Description |
|-------|---------|-------------|
| `issuer` | auto-detect | OIDC issuer URL (e.g. `https://login.example.com/realms/myrealm`) |
| `autoDetect` | `true` | Auto-detect issuer from network traffic |
| `probeEndpoints` | `true` | Probe all discovered endpoints for reachability |
| `testDynamicRegistration` | `false` | Open registration probe (**requires `safetyMode: "active"`**) |
| `testGrantTypes` | `false` | Actively probe token endpoint with detected client IDs to verify if dangerous grant types are usable |
| `validateRpTokens` | `true` | Validate JWTs visible in the browser (signature when JWKS available, iss/aud/exp/nonce) |
| `clientId` | auto-detect | Explicit client_id to test. If omitted, auto-detected from network log |
| `timeoutMs` | `20000` | HTTP request timeout |

**Response:** `issuer`, `configurationUrl`, `configurationFound`, `totalFindings`, `findings[]`, `summary`, `endpointProbes[]`, `grantTypeProbes[]`, **`session`**, **`dossier`** (binding `spa`|`bff`|`confidential`|`bearer-api`, clientId, redirectUri, PKCE, artifact handles, `nextActions`), **`rpTokenFindings[]`**, `errors[]`, `elapsedMs`.

**MCP:** `browser_security_oidc_analyze`.

### POST /api/security/oauth-flow-test
**OAuth2/OIDC authorization-flow security testing** — complements `oidc-analyze` (static provider config) with front-channel flow analysis and active manipulation probes.

**Passive analysis** (`passiveOnly: true` or `safetyMode: "passive"` — allowed under CLI `--safe` on REST; not blocked by `--safe-probes-only`):
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
- Authorization-code **replay** at the token endpoint (uses a code captured from the network log; `useCanaryTokenExchange: true` for legacy forged-code canary)
- Same-origin `redirect_uri` variants (path/query tricks) in addition to evil-origin tests

Uses browser `fetch` with `redirect: "manual"` (server-side fallback with session cookies) for redirect chain analysis.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | `"active"` required for active probes. `"passive"` is treated like `passiveOnly: true`. (`confirmBackend: true` accepted as legacy alias). With `--safe-probes-only`, `"active"` in the body is capped to `"safe"` — see error fields `effectiveSafetyMode` / `cappedBy`. |
| `passiveOnly` | `false` | Network-log + browser leak analysis only (same as `safetyMode: "passive"`) |
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
| `skipTokenExchange` | `false` | Skip code replay at token endpoint |
| `useCanaryTokenExchange` | `false` | Forged code when no captured code exists |
| `holdCallback` | `false` | Reserved for future callback-intercept probes |
| `flowBreaker` | `false` | After HTTP probes, confirm flagged mutations in browser (may consume auth codes; requires `active`) |
| `maxBrowserSteps` | `2` | Max live authorize navigations for flowBreaker (1–5) |
| `mutations` | — | Explicit authorize URLs for flowBreaker browser steps |
| `timeoutMs` | `15000` | Per-probe timeout |

**Response:** `flowsCaptured`, `capturedFlows[]`, `totalFindings`, `findings[]`, `probes[]`, `summary`, `errors[]`, **`dossier`**, **`authSignals[]`**, **`nextActions[]`**, `elapsedMs`. With `flowBreaker`, findings may include `category: flow-breaker` and landing surface (`query`, `fragment`, `postMessage`, `window.name`, `form_post`, **`saml-acs-post`** when a SAMLResponse lands on ACS).

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
  "payload": "<img src=x onerror=\"window.__xss_proof=1\">",
  "effectCheck": "window.__xss_proof === 1",
  "skipInjection": true,
  "waitAfterRenderMs": 500
}
```

**Response `data`:** `verified`, `effectObserved`, `effectValue`, `evidence` (`payloadDelivered`, `renderPageLoaded`, `effectCheckResult`, `screenshot`, `injectionStatus`, …), `cleanedUp`, `error`, `elapsedMs`. Implemented as a thin wrapper over **verify-workflow** (trigger inject + oracle `effectCheck`).

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
| `vars` | No | Object of template variable overrides merged after auto-substitution. Aliases: `substitutions`, `templateVars`. Same keys may also be passed top-level. |
| `exportEvidence` | No | Export bundle on success/failure |
| `exportTrwPath` | No | Copy `scenario.trw` from bundle to repo path after prove |

**Template vars:** when a proof template needs placeholders not derivable from findings (e.g. `transaction-rollback-proof`), pass them in `vars`. Example: `{ "vars": { "balanceUrl": "https://host/api/Balance", "step1Url": "…", "step1Body": "{…}", "step2Url": "…", "step2Body": "{…}" } }`. Non-string JSON values are serialized into the template as raw JSON. **`transaction-rollback-proof`** requires readable balance GETs (HTTP 2xx, JSON body) before and after the mocked failure — identical 401 HTML error pages do not prove rollback.

**Journal:** proofs write observation entries (`chain-prove`, `evidence-export` tags).

**Failure diagnostics:** when `proven: false`, response includes `failurePhase`, `failureDetail`, `templateExpanded`, `attemptedSubstitutions`, and `stepErrors[]`.

**MCP:** `browser_security_chain_prove`. Full chains show `provable`, `missingIdentities[]`, and `suggestedAction` (chain-prove → `/api/repro/verify`).

### POST /api/repro/capture
Build a `.trw` workflow from journal actions since a checkpoint. This is where checkpoints earn their keep: the slice is "what happened since we last synced", not an arbitrary last-N.

```json
{ "checkpointId": "a1b2c3-c1", "name": "checkout-bug", "path": "C:\\\\repros\\\\checkout.trw" }
```

`checkpointId` is optional (defaults to the latest checkpoint, or all replayable actions if none exist). Optional `oracle` is attached to the workflow; without one, verify treats successful steps as a pass. Response: `{ checkpointId, journalIndex, stepCount, skipped, path?, workflow }`.

**MCP:** `browser_repro_capture`.

### POST /api/repro/verify
Replay a captured `.trw`, an evidence bundle directory, or an inline workflow **k times**. Clears the session between runs by default and can apply a named identity. Returns `reproducible` | `flaky` | `not-reproducible` (or `inconclusive` if `expect` mismatches) plus a pass `rate`.

**Requires** `safetyMode: "active"`. Blocked in `--safe` mode.

| Field | Required | Description |
|-------|----------|-------------|
| `trwPath` / `file` | one of | Path to a `.trw` or `.json` scenario |
| `bundlePath` | one of | Directory with `workflow.json` or `scenario.trw` (from `verify-workflow` `exportEvidence`) |
| `workflow` / inline phases | one of | Same shape as `verify-workflow`, or flat `steps[]` |
| `runs` | No | How many times to replay (default `1`, max `20`) |
| `clearSession` | No | Clear test artifacts between runs (default `true`) |
| `identity` | No | Identity name to apply before each run |
| `expect` | No | `reproducible` / `flaky` / `not-reproducible` (also accepts `VERIFIED` / `NOT_VERIFIED`) |
| `safetyMode` | Yes | `"active"` |

Response: `{ verdict, rate, passed, failed, runs: [{ run, passed, error, workflow }] }`.

For fix verification after a patch, set `expect: "not-reproducible"` (the old evidence-rerun `NOT_VERIFIED`).

**MCP:** `browser_repro_verify`.

### GET /api/vpx/export
Export session findings as a **VPX 1.1** document (Vulnerability Proof eXchange). Spec: [`../securitykit/VPX/spec/VPX-1.1.md`](../securitykit/VPX/spec/VPX-1.1.md). VPX 1.0 documents are still accepted on import.

| Query | Default | Description |
|-------|---------|-------------|
| `profile` | `compact` | `compact` or `full` |

**Response:** VPX JSON (`Content-Type: application/vnd.vpx+json`). Includes `runs`, `surfaces`, `findings` (shadow + auto-scan + manual chain-findings), `assessments`, `proofs` (from `verify-workflow` / `chain-prove` in session), `artifacts`, and derived `verdicts`. Proof `oracle.actualSignal` is exported as a **string** (JSON-serialized when the underlying evidence is structured) so documents **round-trip** through import.

Link proofs to findings with `vpxFindingId` on workflow bodies. **Gate-free** — allowed in safe mode.

**MCP:** `browser_vpx_export` — optional `profile`.

### POST /api/vpx/import
Import a VPX 1.1 document into the session (VPX 1.0 is also accepted) — registers findings for proof queue (`source: vpx-import`), surfaces, runs, assessments, proofs, artifacts, and verdicts.

| Field | Default | Description |
|-------|---------|-------------|
| `document` | — | VPX object (or pass document fields inline) |
| `mode` | `merge` | `merge` or `replace` (replace clears prior import) |
| `action` | — | `clear` — remove imported VPX state |

**Response:** `findingsImported`, `findingsSkipped`, `proofsImported`, `verdictsImported`, `surfacesImported`, `documentId`, `warnings[]`. Skipped duplicate finding ids are listed in `warnings[]`. `oracle.actualSignal` accepts a string or JSON object on import.

**Gate-free** — allowed in safe mode. After import, run proofs with `vpxFindingId` on workflows, then `GET /api/vpx/export` for merged document.

**MCP:** `browser_vpx_import`.

### POST /api/vpx/clear
Clear in-session VPX state (imported documents, merged findings queue, and related session artifacts). Use between iterative playbook runs. **Gate-free.**

**MCP:** `browser_vpx_clear`.

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

Use `{{CALLBACK}}` in fuzz payloads — auto-substituted with callback URL (ASCII-safe). Legacy section-sign CALLBACK marker is still accepted.

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

Manual add via `POST /api/security/chain-findings` (or alias `POST /api/security/chain-findings/add` with the finding body at the top level) requires `category` from `knownCategories`. POST body `action`: `add` (default), `remove` (`id`), or `clear`.

### GET /api/security/findings

Unified security findings export for the current scope (shadow, scanners, manual chain entries). **Gate-free.**

| Query param | Description |
|-------------|-------------|
| `host` | Scope host (default: current page host) |
| `allHosts` | `true` — include all hosts in the export |
| `category` | Filter by category substring |
| `severity` / `minSeverity` | Minimum severity |
| `minConfidence` | Default `likely` |
| `includeHygiene` | `true` — include hygiene-class items |
| `includeShadow` | Default `true` |
| `includeChain` | Default `true` |

**MCP:** use chain/analyze tools; REST is the structured export for VPX and external tooling.

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

### Server-Sent Events (SSE)

`text/event-stream` responses are logged as **Fetch** rows with `isEventStream: true` (`GET /api/network?eventStream=true`). Rows are recorded when headers arrive (not when the stream ends), so **fetch() + ReadableStream** consumers appear in the network log while the connection is still open.

**Message capture (two sources, merged in `SseManager`):**

1. **Native `EventSource`:** CDP `Network.eventSourceMessageReceived`
2. **`fetch()` / any consumer:** CDP `Network.dataReceived` chunks when available; linked network row and SSE ingest use **4 MiB** (`bodyCaptureLimitChars` on `isEventStream` rows; ordinary Fetch rows stay **100 KiB**)
3. **CDP live body (open `fetch()` streams):** While a stream is still open, Trowser polls CDP `Network.getResponseBody` (2s UI timer + refresh on `GET /api/sse/*`, audits, and `loadingFinished`). Snapshots grow the linked network row and parse into messages (`captureMode` includes `network-body`). WebView2 often does not emit `Network.dataReceived` for these streams — this path is the primary capture for live `fetch()` + `ReadableStream` consumers.

Connection payloads include `wireBytes`, `captureMode`, and `networkEntryId` when correlated.

### GET /api/sse/connections · GET /api/sse/messages

List captured SSE streams and messages for the active tab. **Gate-free.**

| Query (`connections`) | Description |
|-----------------------|-------------|
| `url` | URL substring |
| `state` | `open`, `closed`, or `all` |

| Query (`messages`) | Default | Description |
|--------------------|---------|-------------|
| `connectionId` | — | Filter to one stream |
| `event` | — | Event name filter |
| `limit` | `100` | Max messages |

**MCP:** `browser_sse_connections`, `browser_sse_messages`.

### POST /api/security/sse-audit

Audit EventSource / `text/event-stream` traffic: **cors-credentials**, **sensitive-data**, **event-data-sink** (page scripts), **coverage**, and optional active checks (**unauthenticated**, **cross-origin**, **last-event-id**, **peer**). Active GET subscribe is allowed at `safe` with `maxMs` / `maxEvents` caps; POST streams need `active`. **Blocked in safe mode.**

**Response `data`:** `auditVerdict` is `complete`, `incomplete`, or `no_traffic`. When event payloads were not captured, `skippedChecks` lists checks that did not run (e.g. `sensitive-data`) — **`findings: []` is not a clean bill of health** in that case. `coverage` includes `messagesCaptured`, `wireBytesCaptured`, and `captureModes`.

For **unauthenticated** proof without cookies, prefer **`POST /api/fetch-direct`** with `includeBrowserCookies: false` when you need a deterministic HTTP status. Active SSE probes may return **inconclusive** on **HTTP 400** when required request headers are missing (shape validation, not authentication).

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | effective CLI mode | `safe` or `active` |
| `connectionId` | all | One stream |
| `checks` | `["all"]` | Subset of check names |
| `maxEvents` | `50` | Active read cap |
| `maxMs` | `5000` | Active read time cap |
| `useCapturedShapeHeaders` | `true` | Active probes copy non-auth owner request headers (excludes Cookie/Authorization) to separate 400 validation from auth |

**MCP:** `browser_security_sse_audit`.

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

Active WebSocket message fuzzing. Sends payload catalogs (`xss-basic`, `sqli-basic`, `json-breaking` by default) via `websocket/send`, inspects received frames for reflection/HTML/SQLi indicators, and replays privileged JSON **message types** from captured traffic. Sends **`ws-code-exec-oracle`** probes first (`__trowser_exec` / `__xss_proof`) to detect inbound frames executed via `eval` / `Function`, in addition to reflection/HTML oracles in later frames.

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

### POST /api/security/websocket-authz

Cross-identity WebSocket check. Sends **one captured sent frame** on a **peer's already-open socket** and classifies what comes back with the same verdict words as Live Authz Shadow (`ConfirmedLeak`, `BolaSuspected`, `SameShapeDifferentData`, `ProperlyDenied`, `NeedsReview`, `Inconclusive`). This is not HTTP BOLA and not Endpoint Probe's Peer button. A peer with no live socket for that URL is `Inconclusive`.

Denial is a close, an error frame, or silence — not an HTTP 403. Silence is `ProperlyDenied` at low confidence.

**Safety gate:** Blocked in `--safe`. Read-like frames (`subscribe`, `unsubscribe`, `query`, `get`, `read`, `list`, `fetch`, `ping`, `pong`, `heartbeat`, `connection_init`) require `safetyMode: "safe"` or higher. Any other frame, including JSON with no type, requires `safetyMode: "active"`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | `safe` | `safe` for read-like frames; `active` for everything else |
| `connectionId` | — | Owner connection from `GET /api/websocket/connections` |
| `frameId` | latest sent text frame | Optional sent frame id |
| `message` | captured frame | Optional replacement payload |
| `peer` | all registered peers | One peer name |
| `responseWaitMs` | `800` | Wait after send before reading the peer's new frames |

**Response `data`:** `connectionId`, `url`, `message`, `writeLike`, `ownerObservation`, `results[]` (`peer`, `verdict`, `confidence`, `reason`, `outcome`, `peerFrames`, `peerError`). Results are also appended to the Live Authz Shadow log as method `WS`.

Live Authz Shadow does not replay sockets. An open socket is a coverage gap (`skippedWebSocket`, kind `websocket`) until this check runs. The Live Authz Shadow window lists open sockets with **Test socket authz**.

**MCP:** `browser_security_websocket_authz`.

### POST /api/security/cswsh-test

**Cross-Site WebSocket Hijacking** test. Runs **browser** cross-site `WebSocket` from mocked `evil.trowser.test` by default (`browserProof`: `true`), plus optional **raw TCP screening** (manual `Cookie` header — may differ from WebView2). Blocked in safe mode.

| Field | Default | Description |
|-------|---------|-------------|
| `url` | auto-detect | Target WebSocket URL (ws:// or wss://). Auto-detects from active connections if omitted. |
| `browserProof` | `true` | When true, WebView2 attacker-page proof is authoritative for `vulnerable` |
| `origin` | `https://evil.trowser.test` | Attacker origin for browser mock (and raw TCP `Origin` header) |
| `cookies` | — | JSON object of cookies to include in handshake |
| `protocol` | — | Sec-WebSocket-Protocol to request |
| `sendAfterConnect` | — | Message to send after connection (e.g. GraphQL `connection_init`) |
| `preset` | — | `"graphql-ws"` auto-fills `sendAfterConnect` with `connection_init` |
| `graphqlPayload` | — | Optional JSON for GraphQL WS `connection_init` payload |
| `monitorMs` | `5000` | How long to listen for incoming messages after connecting |
| `timeoutMs` | `10000` | Connection timeout |

**Response `data`:** `targetUrl`, `vulnerable`, `severity`, `detail`, `proofMode` (`browser` \| `browser+screening` \| `screening`), `screening` (raw TCP), `browser` (connection opened, messages), `browserModel`, plus legacy `handshakeStatus`, `receivedMessages[]`, `evidence`, `elapsedMs`.

Vulnerable findings are auto-pushed to **Shadow Mode**.

**MCP:** `browser_security_cswsh_test`.

### POST /api/validate-html
HTML markup validation (html-validate). No params needed.

### POST /api/seo
On-page SEO audit: document title, meta description, robots, canonical, Open Graph / Twitter cards, hreflang, JSON-LD, and h1 count. **Gate-free** (passive DOM read).

**MCP:** `browser_seo`.

### POST /api/attack-form
Adaptive **“attack this form”** probe: discovers editable fields wired to a form/submit control, infers semantic types, and tests client-side validation gaps (unenforced required/pattern/min/max, email/number/date built as plain text, unbounded length). Default does **not** submit.

| Field | Default | Description |
|-------|---------|-------------|
| `target` | primary form | CSS/semantic selector for form, submit button, or field |
| `submit` | `false` | When `true`, also replays server-side (5xx, stack traces, reflected XSS) — requires `safetyMode: active` |
| `maxFields` | — | Cap fields to probe |
| `perField` | — | Per-field probe budget |

**MCP:** `browser_attack_form`.

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
**Method: POST** (body `{}` or omitted — not GET). DOM XSS audit (passive). Scans page DOM for XSS-prone patterns: inline event handlers, `javascript:` URLs, dangerous sinks (`eval`, `document.write`, `innerHTML`), cross-domain scripts without SRI, `data:` URIs in iframes, external form actions, base tag hijacking. Also reports **`dom-xss-flow`** findings when URL/DOM sources (`location.hash`, `location.search`, `document.referrer`, etc.) appear near dangerous sinks in inline scripts — with `source`, `sink`, and `confidence` fields. No params needed. Inspired by OWASP ZAP passive scan rules.

**MCP:** `browser_security_xss`.

### POST /api/security/xss-scan
Active XSS scan with **unified findings**. Reflected path: character-survival fingerprint → context-driven payloads → optional **DOM verify** (sink/CSP oracles) on `standard`/`deep`. DOM path: navigate + auto-bypass. No noisy default `javascript:` iframe payload.

**Not a substitute for DOM XSS on the current URL:** alias **`POST /api/security/xss-dom-audit`** points here — **not** `dom-xss-audit`. For hash/search/client-side DOM sources on the page you are viewing, prefer **`POST /api/security/dom-xss-audit`** or targeted **`trace-input`**.

**Safety gate:** `"safetyMode": "active"`.

| Field | Default | Description |
|-------|---------|-------------|
| `safetyMode` | — | **Required.** `"active"` |
| `url` + `paramName` | — | Explicit base URL + parameter (reflected + DOM candidates) |
| `request` | — | Optional `{ url, method?, headers?, body? \| json? }` with `§marker§` / `{{marker}}` |
| `depth` | `standard` | `quick` \| `standard` \| `deep` (deep enables stored by default) |
| `payloadProfile` | `"small"` | `small` (built-in) \| `big` (external corpora when available; still capped) |
| `includeReflected` | `true` | Fetch-based reflection analysis |
| `includeDom` | `true` | Navigate + sink monitor |
| `includeStored` | from depth | Stored XSS POST+readback |
| `maxCandidates` | from depth | Cap on discovered candidates |
| `maxBypassAttempts` | from depth | Auto-bypass variants per DOM candidate |
| `timeoutMs` | `10000` | Per-probe timeout |
| `minConfidence` | `likely` | Filter findings |
| `includeHygiene` | `false` | Include non-exploitable tiers |

**Response:** unified envelope. Categories: `xss-reflected`, `xss-dom`, `xss-stored`. **`progress[]`** lists candidate stages (`dom-verify`, `dom-probe`, `stored-xss pass`) so long DOM phases are visible before `elapsedMs` completes.

**MCP:** `browser_security_xss_scan`.

### POST /api/page-text/structured
Extract all page text in a structured format for proofreading. Returns `headings` (with hierarchy), `paragraphs`, `links` (text + URL), `buttons`, `labels`, `images` (alt + src), `metaDescription`, `language`, `wordCount`, `allText`. No params needed.

### POST /api/consistency
GUI consistency & image optimization audit. Analyzes computed styles to count distinct font families, font sizes, text/background colors, button/input heights, and spacing values. Also checks images for optimization issues (oversized images, missing dimensions, missing lazy loading). Warns when counts exceed thresholds (e.g., >4 font families, >10 text colors). No params needed.

### POST /api/third-party
Third-party resource inventory. Scans for external scripts, stylesheets, iframes, and fonts. Classifies third-party hosts via **tldts** (Public Suffix List / eTLD+1) so same-site subdomains (e.g. `cdn.example.com`) are not mislabeled. Reports domains, transfer sizes (from Performance API), and Subresource Integrity (SRI) coverage. Useful for privacy audits, GDPR compliance, and supply chain security. No params needed.

Each `resources[]` entry includes both **`hostname`** (full host, e.g. `fonts.googleapis.com`) and **`etldPlus1`** / **`domain`** (registrable domain, e.g. `googleapis.com`). Note: cross-origin resources served without `Timing-Allow-Origin` report `sizeBytes: 0` (opaque `transferSize`).

### POST /api/security/mixed-content
Mixed content detection. On HTTPS pages, finds all resources loaded over HTTP. Reports element tag, attribute, URL, and severity (High = scripts/iframes, Medium = images/stylesheets, Low = other). Returns clean result on HTTP pages. No params needed.

### POST /api/security/source-maps
Source map & debug mode audit. Detects `sourceMappingURL` directives in HTML/JS/CSS, probes for accessible `.map` files (information disclosure — original source code), and checks for debug globals (Angular `ng.probe` / `getAllAngularRootElements`, React DevTools hook, Vue DevTools hook, Redux DevTools). Severity: HIGH = accessible `.map` files, MEDIUM = sourceMappingURL references, LOW = debug mode indicators. Each finding includes a **`recommendation`**: source-map hits advise removing or restricting `.map` files; debug-mode hits advise disabling the framework's debug APIs in production (`enableProdMode()` for Angular). Debug mode is **not** a source-map issue. No params needed.

### POST /api/security/tech-stack
Technology stack fingerprinting. Detects web servers (Nginx, Apache, IIS, Kestrel, etc.), frameworks (ASP.NET, Express, Django, Rails, Laravel, Spring), languages (PHP, Java, Python, Ruby), JavaScript libraries/frameworks (React, Angular, Vue, jQuery, Next.js, Bootstrap), WAFs (Cloudflare, Akamai, Imperva/Incapsula, Sucuri), CDNs (CloudFront, Vercel, Netlify, Fastly), CMSes (WordPress, Drupal, Shopify), and analytics (Google Analytics, Hotjar, Segment). Combines HTTP response headers, cookies, DOM patterns (meta tags, data attributes, global JS objects), and script URL analysis. Each detection includes `name`, `version` (if available), `category`, `evidence`, `source`, and `confidence` (0–1). No params needed. Included in `POST /api/audit-all`.

**Response:** `detectionCount`, `categories`, `detections[]`, `frameworks[]`, `servers[]`, `jsLibraries[]`, `waf[]`, `cdn[]`, `cache` (`detected`, `vendors`, `documentStatus`, `cacheable`, `vary`, `evidence`), `elapsedMs`, `summary`. A cache is not a vulnerability; if `cache.detected`, follow up with `POST /api/security/cache-map` then `POST /api/security/cache-pollution-scan`.

**MCP:** `browser_security_tech_stack`.

### POST /api/security/cookies
Cookie security audit (OWASP best practices). **Reconciles** cookie-jar data with **Set-Cookie headers from the network log** (authoritative for HttpOnly/Secure/SameSite — fixes false positives when HttpOnly cookies are invisible to `document.cookie`). Checks all cookies for: missing Secure flag on HTTPS (on HTTP origins the Secure checklist item is **skipped**: `skipped: true`, `pass` omitted, summary status **`[SKIP]`** — not a failure), **HttpOnly** on session/auth cookies (name-pattern heuristics **plus** non-expiring session cookies that are not known analytics/consent names — e.g. app-named tokens), **explicit SameSite** on session cookies (browser default Lax is not treated as an application choice), SameSite=None issues, overly broad domain scoping, and excessive cookie lifetimes. **Known vendor analytics cookies** (Dynatrace `dtPC`/`dtSa`/`dtCookie`/`rxvt`/`rxVisitor`, Hotjar `_hjSession*`/`_hjId`, Google Analytics `_ga*`/`__utm*`, Facebook Pixel `_fbp`/`_fbc`) are **excluded from HttpOnly checks** — these are JS-readable by design. Returns `findings`, `checklist`, `primarySource`, and `networkReconciledCookies`. Falls back to CDP `Network.getCookies` when WebView2 CookieManager is unavailable. Included in `POST /api/audit-all`. No params needed.

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

**Response:** `{ targetUrl, modifications, responseStatus, responseStatusText, responseUrl, redirected, bodyLength, response, timestamp }`. `response` is a body snippet (up to 2000 chars) from the ACS response when parse succeeds; on fetch errors, `responseStatusText` may carry the error message.

**MCP:** `browser_saml_replay`

---

## Security Orchestration (Playbooks)

Goal-oriented orchestration layer: one call per OWASP category, one prioritized report. Each playbook composes Trowser's existing primitives (auto-scan, CORS sweep, secrets harvest, supply-chain scan, etc.) into a sequenced pipeline with unified safety, depth, and budget controls.

> **Browse manually, then scan with `crawl: false`.** Playbooks default to **`crawl: false`** — they scan traffic already in the network log. Browse login, search, and CRUD flows first; set **`crawl: true`** only when you want the playbook to auto-discover links/forms before scanning. For probe-heavy playbooks (`a05-injection`, `a01-access`, …), set **`scope.targetUrl`** to one captured endpoint for a fast focused run, or **`depth: "deep"`** for explicit broader coverage (default standard depth probes at most **2** endpoints site-wide). Agent sessions: prefer **`a05a-injection-core`** (then `a05b` / `a05c`) or **`depth: "llm"`** with a 120–300s budget instead of full A05’s ~1800s recommendation.

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
  "budget": { "maxSeconds": 300, "maxRequests": 800 },
  "evidence": "auto",
  "emitSuggestedProofs": true,
  "tags": ["pre-prod", "sprint-42"],
  "format": "vpx-compact",
  "embedVpx": false,
  "persistVpx": true
}
```

**Canonical budget workflow:** `POST /api/orchestrate/dry-run/{id}` → copy `recommendedBudget` into the real run. The default `maxSeconds: 120` often yields `coverageIncomplete` / `skippedByBudget` on probe-heavy playbooks — do not treat 120s as a normal envelope.

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
| `depth` | `"standard"` | `quick` (1 probe endpoint, passive scans up to 5) · `llm` / `agent` (short agent profile, 1 probe endpoint, ~120–300s budgets) · `standard` (2 probe endpoints, passive up to 20) · `deep` (broader probe coverage — up to 100 endpoints, explicit opt-in) |
| `crawl` | `false` | Alias for `includeCrawl`. When `false` (default), skips the shared `crawl-light` step — **use after manual browsing** |
| `includeCrawl` | `false` | When `false` (default), skips the shared `crawl-light` step. Prefer `crawl` for brevity |
| `scope.targetUrl` | — | **Recommended for probe playbooks.** Restrict scanners to one captured endpoint URL (must exist in network log). Caps probe steps to that endpoint |
| `scope.targetMethod` | — | Optional method with `scope.targetUrl` (e.g. `POST`). Alias: `scope.target.url` / `scope.target.method` |
| `async` | `false` | When `true`, return HTTP **202** immediately and run the playbook in the background. Poll `GET /api/orchestrate/runs/{runId}` until `status` is terminal |
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

### GET /api/orchestrate/runs/{runId}

Poll an **async** playbook run started with `"async": true` on `POST /api/orchestrate/{id}`. Gate-free (in-memory status only).

**Response (`data`):** `{ "runId", "playbookId", "status": "queued"|"running"|"completed"|"failed"|"cancelled", "createdAt", "startedAt", "finishedAt", "currentStep", "stepsExecuted", "pollUrl", "error?", "result?" }`. When `status` is `completed`, `result` matches the synchronous playbook envelope (`findings`, `vpx`, …).

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
  ],
  "coverageIncomplete": false,
  "agentInstruction": null
}
```

When any step has `skippedByBudget: true`, the dry-run sets **`coverageIncomplete: true`** and a one-line **`agentInstruction`** telling agents to raise the budget before executing.

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
| `smuggling-passive` | any | Ambiguous response framing (TE+CL / conflicting CL). Via/CDN is context, not a finding |
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

**A14 Other.** Steps: crawl → smuggling indicators → active smuggling → host-header injection → cache-identify → cache-map → cache-pollution → cache deception → cache poisoning → open redirect → WebSocket fuzzing.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `smuggling-passive` | any | Ambiguous response framing only (Via / CF-Ray / X-Cache are context, not findings) |
| `smuggling-active` | `active`+ | CL-TE / TE-CL raw TCP; playbook ingest is **confirmed differential 404 only** |
| `host-header-injection` | `active`+ | Host override, X-Forwarded-Host, duplicate Host, port manipulation, absolute-URL probes |
| `cache-identify` | any | Passive cache identification from document headers (vendors, HIT/MISS/DYNAMIC/no-store). A cache is **not** a finding. |
| `cache-map` | `safe`+ | Key-mapping with unique busters (header probes when `active`) |
| `cache-pollution` | `active`+ | Live-key: miss-forcing header, error store, clean GET confirm. Skipped when identify/map find no cache. |
| `cache-deception` | `safe`+ | Path confusion to cache authenticated responses publicly |
| `cache-poison` | `active`+ | Unkeyed header canary; uses pollution `bypassHeader` when found. Skipped when identify/map find no cache. |
| `open-redirect` | `safe`+ | Redirect parameter scanning with bypass payloads |
| `websocket-audit` | `safe`+ | WebSocket message injection and message-type confusion fuzzing |

**`nextActions` hints:** `a01-access` (when **confirmed** http-smuggling), `a04-crypto` (when cache issues), `a07-authn` (when host-header or open redirect).

### POST /api/orchestrate/a05-injection

**A05 Injection (full).** Steps: crawl → attack-surface → injection scan (SQLi, XSS, SSTI, NoSQL, LDAP, cmd-canary, parser-probe, prototype-pollution, CSTI, path-traversal) → SQLi login sweep → deserialization + file upload. Recommended budget ~1800s. For LLM/agent sessions prefer the split playbooks below or `depth: "llm"`.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log (5/15/50 pages by depth) |
| `attack-surface` | any | Passive network-log analysis, injectable endpoint classification |
| `injection-scan` | `safe`+ | SQLi, XSS, SSTI, NoSQL, LDAP, cmd-canary, parser-probe, prototype-pollution via AutoScanPipeline (read-only in `safe`, write verbs in `active`+) |
| `sqli-login-sweep` | `active`+ | SQL injection bypass on common login endpoints |
| `deserialization-scan` | `active`+ | Insecure deserialization gadgets and file upload validation bypass |

**`nextActions` hints:** `a01-access` (when SQLi found), `a07-authn` (when XSS/template injection), `a11-ssrf` (when cmd injection); header/body re-probe templates when non-query sinks appear in the surface.

### POST /api/orchestrate/a05a-injection-core

**A05a Injection Core** (~300s). cmd-canary + XSS + SQLi only. Ideal first pass for agent sessions. `nextActions` point at `a05b` / `a05c`.

### POST /api/orchestrate/a05b-injection-templates

**A05b Injection Templates** (~600s). SSTI, SSTI-polyglot, CSTI, NoSQL, LDAP, path-traversal. Run after `a05a`.

### POST /api/orchestrate/a05c-injection-advanced

**A05c Injection Advanced** (~600s). Parser-probe, prototype-pollution, SQLi login sweep, deserialization + file upload. Run after `a05a`/`a05b`.

### POST /api/orchestrate/a06-design

**A06 Insecure Design.** Steps: crawl → attack-surface → workflow-step-skip → race-condition → fail-open → missing-parameter → mass-assignment (price/role/status).

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log |
| `attack-surface` | any | Passive network-log analysis — discovers POST/PUT/PATCH endpoints and feeds URLs to downstream steps |
| `workflow-step-skip` | `active`+ | Detect multi-step workflows from network log and test if intermediate steps can be bypassed |
| `race-condition` | `active`+ | Concurrent POST burst on single-use endpoints (coupons, transfers, votes). Uses attack-surface URLs. |
| `fail-open` | `safe`+ | Test sensitive endpoints with missing/invalid auth tokens (no simulated post-500 branch) |
| `missing-parameter` | `active`+ | Omit required JSON fields to test crash vs graceful validation. Uses attack-surface POST URLs. |
| `mass-assignment-design` | `active`+ | Mass-assignment with price/role/status fields targeting business logic |

**Workflow step-skip detection:** The `workflow-step-skip` step identifies multi-step workflows (e.g., checkout: cart → address → payment → confirm) by analyzing consecutive POST/PUT/PATCH requests with shared path prefixes and timing correlation. It then replays the final step without intermediates. If the server returns success when prerequisites were skipped, the workflow likely lacks server-side state enforcement.

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

**A12 Availability.** Steps: crawl → costly-operations (passive) → rate-limit audit → body-size limit → ReDoS scan → GraphQL query-cost analysis (including worst-case nested query cost probes in active mode).

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log |
| `costly-operations` | any | Passive single-request cost risks from traffic/DOM (paging, heavy routes, bulk input, compose-links) |
| `rate-limit-audit` | `safe`+ | Sequential baseline then concurrent burst to detect missing/weak rate limits |
| `body-size-limit` | `active`+ | Escalating body sizes (1KB→1MB) on POST endpoints to detect unbounded acceptance |
| `redos-scan` | `safe`+ | Single-request ReDoS timing oracle on injectable parameters |
| `graphql-cost` | `safe`+ | GraphQL depth/complexity/batching probes (auto-detects endpoint from network log) |

**`nextActions` hints:** `a07-authn` (when missing rate limits on auth endpoints), `a05-injection` (when GraphQL endpoint found).

### POST /api/orchestrate/a13-llm

**A13 AI & LLM.** Steps: crawl → LLM endpoint discovery → corpus red-team (LLM01–03 + LLM05–07 + LLM09) → RAG/memory poison (LLM04/08) → unbounded consumption (LLM10, skipped at `depth: quick`) → output-to-sink tracing.

| Step | Safety requirement | What it does |
|------|-------------------|--------------|
| `crawl-light` | any | BFS crawl to populate network log and discover LLM/chat endpoints |
| `llm-discover` | any | Discover chat endpoints from network log and chat UI widgets from DOM |
| `llm-redteam` | `active`+ | Corpus probes + WebMCP abuse |
| `rag-poison` | `active`+ | Document/memory poison persistence (LLM04); peer isolation via scan API `peerBaseUrl` |
| `unbounded-consumption` | `active`+ | LLM10 flood / oversized / max-output / tool-loop (not at quick depth) |
| `output-sink-trace` | `active`+ | Instrument DOM sinks then fire canary-tagged prompts to prove injection → XSS chain |

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
| `playbook-a14-other` | `active`+ | Smuggling, host-header, cache identify/map/pollution/poison |
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

Each VPX finding includes OWASP and CWE classifications as first-class fields. The `owasp` field uses **TrowserTwelve** taxonomy (not OWASP 2021 numbering). **Twelve category playbooks** use IDs **A01–A07, A09, A11–A14**; **A08** (software/data integrity) and **A10** (unused; SSRF is **A11**) have no dedicated playbook — integrity coverage is primarily **A03**. Key remaps vs OWASP 2021: A02=Misconfiguration, A03=Supply Chain, A04=Crypto, **A05=Injection**, A06=Insecure Design, A11=SSRF, A12=Availability, A13=AI/LLM, A14=Other.

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
| `owasp` | Trowser-Twelve category ID: `A01`–`A07`, `A09`, `A11`–`A14` (see orchestration playbooks; A08/A10 unused) |
| `cwe` | Array of applicable CWE identifiers |
| `description` | Detailed explanation of the issue |
| `remediation` | Actionable fix guidance |
| `reference` | OWASP/MDN reference URL (when available from scanner) |

### POST /api/vpx/render

Re-render a stored VPX document without re-running the playbook. Useful for format conversion and "re-show last result".

| Field | Default | Description |
|-------|---------|-------------|
| `vpx` | *(required)* | A VPX 1.1 document (JSON object; VPX 1.0 also accepted) |
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

### POST /api/monkey-trowser
**Monkey Trowser** — systematic robustness: clicks every element, fuzzes forms, crawls links. Navigation scope: set in app / CLI, pass **`scope`** for this call only, or leave unset to **auto-scope from the current page** (same registrable domain for the run).

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

## Client TLS certificates

Mutual TLS client certificates for WebView2 HTTPS (stored DPAPI-encrypted, persist across sessions). **Blocked in `--safe` mode** for add/remove/active changes; list/get are allowed.

### GET /api/ssl/certificates
List loaded certificates: alias, subject, issuer, thumbprint, expiry, active flag.

### POST /api/ssl/certificates
Add a `.pfx` / `.p12`: `{ "filePath", "password", "alias" }`.

### DELETE /api/ssl/certificates
Remove by alias: `{ "alias" }`.

### GET /api/ssl/certificates/active
Current active client certificate metadata, or empty when none is set.

### POST /api/ssl/certificates/active
Set active cert: `{ "alias": "my-cert" }`. Empty/null alias clears active (no client cert sent).

**MCP:** `browser_ssl_list`, `browser_ssl_add`, `browser_ssl_remove`, `browser_ssl_get_active`, `browser_ssl_set_active`.

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

### POST /api/peer/spawn
Launch another Trowser on localhost and register it (replaces manual `Start-Process` + `peer/register` for scripts). Uses GUI peer settings when available; otherwise spawns via the same executable with a generated API key in `TROWSER_API_KEY`.

| Field | Default | Description |
|-------|---------|-------------|
| `name` | session or `peer1` | Registered peer name |
| `session` | same as `name` | `--session` profile name |
| `apiKey` | generated | Peer API key (returned once in the response) |
| `port` | next free ≥6924 | `--api-port` |
| `ephemeral` | `true` | Pass `--ephemeral` for throwaway WebView profiles |
| `register` | `true` | Register in the local peer registry after launch |

Response: `{ spawned, name, baseUrl, apiKey, sessionName, alive }`. Waits up to 45s for `GET /api/ping`.

### POST /api/peer/stop
Stop a spawned peer process and optionally unregister it.

| Field | Default | Description |
|-------|---------|-------------|
| `name` | — | **Required.** Registered peer name |
| `unregister` | `true` | Remove from the peer registry after stop |

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
| `timeout` | No | Request timeout in ms forwarded to the peer's fetch-direct (default on peer: 30000). Caller-side forward timeout is **`timeout + 5000` ms** (capped), or **15s** when omitted — dead peers fail fast with **502** like other peer routes. |
| `ensureOrigin` | No | Auto-navigate peer to the target URL's origin if needed, so cookies are sent correctly (default `false`) |

Response: proxied JSON from the peer's `POST /api/fetch-direct` (`data.status`, `data.body`, …).

**Peer forward timeouts:** Reachability-style calls (ping, state/info, fetch without a long operation) use a **15s** client timeout by default. Gate-bound peer work (navigate, screenshot, identity apply, long fetch-direct) uses up to **65s** (above the peer's ~60s automation gate). Unreachable peers return **502** with `Failed to reach peer` rather than hanging for the old 75s default.

**Gate-free design:** `peer/fetch` uses the peer's `POST /api/fetch-direct` endpoint (server-side HTTP with browser cookies) instead of the gated `POST /api/fetch`. This completely avoids gate contention on the peer — requests never block waiting for the peer's WebView2 gate. When the caller does not already send an auth header, the same peer authenticator the shadow uses is applied: the peer's latest `Authorization`, a JWT cookie such as `token`, or a token in `sessionStorage` / `localStorage`.

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
Gate-free **`GET /api/info`** from a peer (current URL, title, session). MCP `browser_peer_state` uses the same path (not gated `/api/state`).

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
**Cross-identity authorization comparison.** Runs the same set of endpoints on both the local session AND a registered peer's session, producing a structured diff with auto-classification (BOLA/IDOR signals).

| Field | Required | Description |
|-------|----------|-------------|
| `peer` | One of peer/peers | Single registered peer name (legacy) |
| `peers` | One of peer/peers | Array of registered peer names — runs diff against each |
| `endpoints` | Yes | Array of URL strings or `{ url, method?, headers?, json?, body? }` objects |
| `includeBody` | No | Include full response bodies in results (default `false`) |
| `includeBodyOnMismatch` | No | Include bodies only when local and peer responses differ (default `false`) |
| `ensureOrigin` | No | Auto-navigate peer to the target origin before fetching (default `true`) |
| `leakTokens` | No | Array of strings to search for in peer responses to detect data leaks (e.g. patient names, user IDs) |
| `bodyMatch` | No | Response comparison: `{ strategy?: "exact"|"normalizedJson"|"structural"|"htmlMain", ignoreFields?: string[] }`. `normalizedJson` strips volatile fields before hashing (defaults include `timestamp`, `requestId`, `sessionId`, etc.). **`htmlMain`** compares `<main>` / `role=main` text (ignores header chrome). **`leakTokens`** on peer 200 responses can promote **`FILTERED_RESPONSE`** to **`BOLA_SUSPECTED`**. |
| `ignoreFields` | No | Shorthand: enables `normalizedJson` with these field names when `bodyMatch` is omitted |
| `structuralMatch` | No | Shorthand: `true` sets `strategy: structural` (compare JSON shape only — use cautiously) |

**Auto-classification logic:**
| Local | Peer | Finding |
|-------|------|---------|
| 200 + same body | 200 + same body | `BOLA_SUSPECTED` ⚠️ |
| 200 | 200 + different body | `FILTERED_RESPONSE` (check manually) |
| 200 | 200 via redirect to login/access-denied page | `REDIRECT_DENIED` ✅ (common with ASP.NET WebForms, Spring Security) |
| 200 | 401/403/404 | `PROPERLY_DENIED` ✅ (404 = common hide-existence denial for owner-only resources) |
| 200 | 500 | `ERROR_BEFORE_AUTH` ⚠️ |
| 401/403 | 401/403 | `DENIED_BOTH` ℹ️ |

Each comparison now includes **redirect info**: `redirected` (boolean) and `finalUrl` (the URL after redirects, when different from the requested URL). This is especially useful for server-side redirect-based authorization (302→login page).

Replays of captured browser requests strip the owner's `Cookie`, `Authorization`, and cache validators (`If-None-Match`, `If-Modified-Since`). The peer browser sends its own `Accept-Encoding`. The body is decompressed before it is compared.

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

### GET /api/authz/model
**Access model.** Read declared intent and identities for one host.

### PUT /api/authz/model
**Access model.** Set per-resource intent and identities for one host.

Declared intent is per `(method, urlTemplate)`, plus identities (role, tier, ownerTags).

**GET** query: `host` (hostname or host:port; defaults to the current page), `seed=true` to heuristic-fill from the attack surface before returning. `example.com`, `example.com:443`, and `example.com:80` are one model. A non-default port stays on the key (`127.0.0.1:8099`). Per-user path nouns (`/order`, `/account`, `/cart`, `/basket`, `/profile`, …) are seeded as sensitive/per-user even when the attack surface has not recorded `authRequired`. Paths that are neither those nouns nor public content (`/blog`, `/catalog`, `/product`, …) stay unclassified. Seeding never overwrites a human or AI classification.

**PUT** body:

| Field | Required | Description |
|-------|----------|-------------|
| `host` | Yes | Hostname or host:port. `:443` and `:80` are stripped. Any other port stays |
| `resources` | No | Array of `{ method, urlTemplate, sensitivity?, ownership?, source?, confidence?, notes? }`. `sensitivity`: `public` \| `internal` \| `sensitive`. `ownership`: `shared` \| `perUser` \| `perTenant` \| `roleGated`. `source`: `heuristic` \| `observed` \| `human` \| `ai` |
| `identities` | No | Array of `{ name, role?, tier?, ownerTags? }`. `ownerTags` are strings (email, username, id) that confirm a leak when they show up in a peer body |

The model is stored under `%LocalAppData%\Trowser\AccessModels\{host}.json`. `POST /api/authz/shadow` `export`/`import` is the way to move it with the result log.

### POST /api/authz/shadow
**Live Authz Shadow.** Watches browsing on this instance and replays successful Document/XHR/Fetch requests, plus JSON and `/api/` calls whatever Chromium labeled them, and authenticated images. Other registrable domains are not replayed. Off until `mode:"enable"`. GUI session only. The Live Authz Shadow dialog has **Export** and **Import** buttons that write and read this same bundle; Import asks whether to replace the current result list.

| Field | Required | Description |
|-------|----------|-------------|
| `mode` | No | `status` (default), `enable`, `disable`, `results`, `clear`, `export`, `import` |
| `safetyMode` | enable | `passive` \| `safe` (default) \| `active` \| `aggressive`. GET/HEAD/OPTIONS/QUERY replay at every mode. POST/PUT/PATCH/DELETE replay only at `active` or `aggressive`; those skips are counted in `skippedBySafetyMode` |
| `peers` | No | Peer names. Empty means every registered peer. Pass an explicit list when a registered peer is down |
| `sinceId` | results | Return only results with `id` greater than this |
| `verdict` | results | Filter to one verdict. Wire values are PascalCase (`ConfirmedLeak`, `BolaSuspected`, `SameShapeDifferentData`, `NeedsReview`, `FilteredResponse`, `ProperlyDenied`, `Inconclusive`, `ReplayedWrite`, `PeerUnauthenticated`). `mode: "export"` uses the same strings. The filter is case-insensitive |
| `path` | export/import | File to write or read. Omit on export to get the bundle inline |
| `bundle` | import | The export object, when `path` is omitted |
| `replaceResults` | import | `true` drops the in-memory log before restoring (default `false`). A human/AI resource classification already stored is not replaced by a heuristic from the bundle |

**Result fields:** `id`, `timestamp`, `host`, `method`, `url`, `urlTemplate` (numeric ids, GUIDs, and long hex object ids become `{id}`; email path segments become `{email}`; identity query names such as `orderId` are kept as `orderId={id}`; other query keys are dropped), `peer`, `verdict`, `confidence`, `reason`, `expectedOutcome`, `needsClassification`, `ownerStatus`, `peerStatus`, `ownerBodyLength`, `peerBodyLength`, `peerFinalUrl`, `peerError`, `ownerTokenCount`, `peerAuthApplied` (`cookie` \| `bearer` \| `both` \| `none`), `ownerBodyMissing`, `htmlShell`, `duplicateHtmlShell`, `peerMutated`.

Replay strips the owner's `Cookie` and `Authorization`. The peer browser sends its own `Accept-Encoding`; the body is decompressed before compare. When that call carried an auth header, the shadow puts the **peer's** current header back, taken from the peer's own later requests, from a JWT cookie such as `token`, and from the peer's `sessionStorage` / `localStorage`. `peerAuthApplied: none` means that credential was not applied. A 401/403/404 on a read in that case is `Inconclusive`, not `ProperlyDenied`. A 200 with the same body, when the owner request itself carried a cookie or `Authorization`, is `ConfirmedLeak`: the peer had no session and received the owner's body. An HTML document, and a request the owner made with no credential, can still recommend public. The same authenticator is applied by `POST /api/peer/fetch` when the caller does not already send an auth header. `fetch()` run through `execute-js` is not browser traffic, so the shadow does not replay it.

Resource type `Other` is not a reason to skip an API call. Scripts, stylesheets, fonts, and decorative images are still skipped (`skippedResourceType`). A 2xx `/contacts` labeled `Other` is replayed.

`FilteredResponse` means the two 2xx bodies differed. It is not a passing authz result. `Inconclusive` includes a peer or owner body that was still compressed or binary, a missing owner body (`ownerBodyMissing: true` — a 0-byte capture is not compared), and a read denial with no peer credential. `ConfirmedLeak` is an owner email or user id inside the peer body, or a 200 that the peer received with no session while the owner was logged in. Harvested tokens are email and user-id fields (`userId`, `username`, `sub`, `uid`) at any depth, emails in the request path, `/me` `/profile` `/whoami` responses, and `ownerTags` you set. A generic `id` is not an owner token, and a value that is already a segment of the replayed URL does not count. The raw email is not written into `urlTemplate`. When two same-shaped JSON bodies contain different emails, the reason says each identity received its own object.

POST/PUT/PATCH/DELETE use write verdicts. A 2xx against a named object (`{id}`, `{email}`, `{token}` in the path) is `BolaSuspected`: the peer completed that save. When the two bodies match once `id` / `_id` are ignored, that is the same document with a new id, not a different resource. `ReplayedWrite` is a collection create where each identity got its own success; `peerMutated` is still true. If those bodies match except an id, the reason says so. `ConfirmedLeak` still requires an owner token in the peer body. `PeerUnauthenticated` means the write ran with `peerAuthApplied: none`.

`htmlShell` and `duplicateHtmlShell` are set only when this route's body hash matches a **different** route. A document that matches across the two sessions, and matches no other route, is an identical public document. Its reason says that, and the Live Authz Shadow dialog still lists it under Needs classification. A duplicate HTML shell is the same document as another route and is not a second classification row. Other registrable domains (maps, youtube, analytics) are not replayed (`skippedThirdParty`). Classification is per `urlTemplate`. The recommended answer comes from the response: an identical public document recommends public; a confirmed leak, a write, a list whose bodies already differ, or an authenticated create recommends per-user. Choosing "Sensitive — per user" makes coverage report a violation if the peer body still matches. The dialog does not open the AI Assistant.

`mode: "clear"` drops the result log and this run's classifications. Replays already in flight for that run are discarded. The dialog's Clear results also turns the shadow off. Classifications live for the process; Export and Import carry them. Skip reasons are stored on the access model, so a gap still says why a write was skipped after clear.

**Status fields:** `enabled`, `safetyMode`, `peers`, `endpointsTested`, `endpointsSkipped` (no peers), `skippedBySafetyMode`, `skippedResourceType`, `skippedNonSuccess`, `skippedThirdParty`, `replayFailures`, `peerMutatedCount`, `resultCount`, `verdictCounts`, `needsClassificationCount`.

Interesting verdicts (`ConfirmedLeak`, `BolaSuspected`, `SameShapeDifferentData`, `ReplayedWrite`) on a resource with no human or AI classification are counted in `needsClassificationCount`, including when the only model entry is a heuristic. `FilteredResponse` and `ProperlyDenied` are not classification verdicts. A duplicate HTML shell is not. Several peers replaying one template are one endpoint.

### POST /api/authz/coverage
**BAC coverage report** for one host. Body: `host` (optional; defaults to the current page), `markdown` (default `true`). `example.com:443` and `example.com:80` resolve to `example.com`. A non-default port is its own key. `coverage.testedPercent` is how much of the surface is classified and/or cross-identity tested. It is not a security score (`percent` is the same number).

Joins the access model, the attack-surface templates, and Live Authz Shadow results. `intentAlignment` and `expectedOutcome` are computed when coverage is read, from the current model plus the stored statuses, lengths, and token match. Classifying the resource and reading coverage again shows the new alignment. Each finding includes the shadow evidence fields plus `intentAlignment`:

| Alignment | Meaning |
|-----------|---------|
| `violation` | Declared deny, but the peer got a leak / same body / same shape — or declared allow, but an owner tag leaked |
| `consistent` | Verdict matches the declaration (including a same body on a public/shared resource) |
| `unresolved` | Declared deny, but the peer got different 2xx content. Not proof of scoping |
| `needs-classification` | No usable declaration, and the verdict is a leak, a same body, or different content |
| `unclassified` | A verdict that is not a leak or a content mismatch (for example `ProperlyDenied`) and the resource has no declared intent |

`nextActions` leads with confirmed leaks and with writes that set `peerMutated`. A replay with `peerAuthApplied: none` is split: a 200 is missing authentication; a denial is inconclusive and means log the peer in. A `FilteredResponse` whose peer credential was applied is called out to compare before closing. A request skipped because `safetyMode` is `safe` is not listed as critical untested work, including after `mode: "clear"`. An owner 403 that was seen and not replayed says so (`skipped` / non-success), instead of "browse this, it was never tested." A host with no shadow results says `No replay results for {host}. The page host is {current}.` It does not say there are no gaps. `localhost` and `127.0.0.1` stay different keys, and the sentence says so when the page is the other one. `PUT /api/authz/model` with `resources: []` or `identities: []` replaces that stored list.

Peer `baseUrl` must be `http://localhost:<port>`. `http://127.0.0.1:<port>` is a 400 and is not stored. HTTP.sys rejects `Host: 127.0.0.1` on the API port.

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
| `PROPERLY_DENIED` | 401/403/404 — access correctly denied ✅ |
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
**Gate-free server-side fetch** using `HttpClient`. Unlike `POST /api/fetch` (which runs `fetch()` inside WebView2 and requires the gate), this endpoint bypasses the gate entirely. Used internally by `peer/fetch` to avoid deadlocks.

| Field | Default | Description |
|-------|---------|-------------|
| `url` | required | Absolute URL |
| `method` | `GET` | HTTP method |
| `headers` | — | Request headers (including optional `Cookie` / `Authorization`) |
| `body` / `json` | — | Request body |
| `timeout` | 30000 | Timeout ms |
| `includeBrowserCookies` | `true` | When `true`, merge the WebView cookie jar for the URL, then overlay any caller `Cookie` header (**caller wins on same cookie name**). When `false`, send **only** caller-supplied `Cookie` / `Authorization` (no jar) — use this for portable-token proofs |
| `cookies` | — | Same as `POST /api/fetch` — one-shot cookie impersonation without touching the jar |
| `identityOverride` | — | `{ "peer": "…" }` or `{ "identity": "…" }` — same semantics as `POST /api/fetch` |

**Response** adds `cookiesSent` (cookie **names** only), `includeBrowserCookies`, `identityUsed` (`browser-session`, `anonymous`, `caller-cookies`, `peer:<name>`, `identity:<name>`, …), and optional `identitySource` for auditability. Values are never echoed. An explicit empty `Content-Type` omits that header instead of failing the request.

### GET /api/session/cookie-header
**Gate-free** cookie header material for an absolute `url` query parameter. Used internally when `identityOverride.peer` is set on fetch; also handy for debugging. Returns `cookieHeader`, `cookieNames`, and `cookieSourceUrl` (full header values — localhost API only; protect your API key).

### GET /api/session/identity

**Live session introspection** (renamed from `GET /api/identity`). Returns session name, domain, redacted cookie previews, JWT cookie inventory, storage tokens, and inferred auth mechanism. **Gate-free.**

**Response `data`:** `sessionName`, `domain`, `currentUrl`, `cookieCount`, `cookies`, `jwtCookies?`, `inferredTokens?`, `inferredIdentity?`

`jwtCookies[]` entries: `name`, `alg`, `exp`, `iss`, `preview` (redacted). Inference prefers cookies whose **values** are JWT-shaped (`eyJ…` / three segments) over opaque cookies whose names merely contain `token`.

Supported auth mechanisms: `shibboleth`, `java-session`, `aspnet`, `oauth`, `jwt-cookie`, `session-cookie`, `storage-token`.

A JWT in `localStorage` or `sessionStorage` (including a key such as `token`) sets `inferredIdentity.mechanism` to `storage-token` and `inferredIdentity.storage` to `localStorage` or `sessionStorage`, even when a session cookie such as `connect.sid` is also present. `sessionCookie` still names that cookie. `inferredTokens` lists the storage entries (redacted).

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

**Setup:** LLM Settings → **MCP client config** (OpenCode / Cursor / Claude Code / Copilot CLI) → **Copy**. Full instructions: [README — Connect an external MCP agent](README.md#connect-an-external-mcp-agent).

```json
{"mcpServers": {"trowser": {"url": "http://localhost:6923/mcp?mode=core", "headers": {"Authorization": "Bearer trowser_YOUR_API_KEY"}}}}
```

**Transport notes:** `POST /mcp` is the JSON-RPC endpoint. `GET` / `DELETE` return **405** (no standalone SSE stream / no session delete — Streamable HTTP 2025-03-26). Empty `POST` bodies return **202** (client probe tolerance). JSON-RPC requests with a body (including `tools/call`) wait on the same operation gate as REST (up to 60s) and return a JSON-RPC result or busy error — never an empty **202**. Parallel MCP calls from clients like Cursor are serialized; on gate timeout the response is JSON-RPC `-32000` with `blockedBy`. LLM Settings → Copy embeds the key for reliability; env-var auth is optional (see README).

**External MCP Mode** (default **Core**): controls which tools appear on `tools/list` / are callable for external clients. **Core** = interact + quality audits + `browser_security_auto_scan` (token-efficient). **Security** = complete MCP surface (core plus specialist scanners, intercept/mock, identities, peers, and `browser_take_screenshot`). Copied LLM Settings configs use `?mode=core`. Per-request override: query `?mode=core|security` (`full` is an alias of security; legacy `economical`, `eco`, `agent`, `chat` → core) or header `X-Trowser-Mcp-Mode`. Built-in AI Assistant Interaction Mode (Chat / Economical / Full) remains separate: Economical is everyday live testing (interact + quality + `browser_security` + screenshot); it is **not** the same allow-list as Core. GitHub Copilot and OpenAI-style Chat APIs cap tools at 128: Full mode sends Core first (including `browser_journal_add` / `_get` / `_export`, console, network, fetch) then fills remaining slots with specialist scanners. `browser_take_screenshot` is listed in built-in Economical/Full and external security, not Chat or `?mode=core` — prefer `format: "jpeg"` for LLM use. **Safe mode** still blocks mutating tools on `/mcp`. Tool JSON payloads are **compact** (not pretty-printed) to save tokens. `GET /api/info` reports `externalMcpMode`.

**Locator naming:** prefer **`byText`** for visible-text locators on both REST and MCP (aligned with REST). On MCP click/hover/etc., plain `text` remains an alias for `byText`. On **`browser_type`**, `text` / `value` are **typed content** (aliases); use `byText` if you need a visible-text locator.

### MCP Tools

| Tool | Description |
|------|-------------|
| `browser_snapshot` | Page state: URL, title, headings, interactive elements, errors (compact JSON) |
| `browser_diff_state` | Diff two refGeneration snapshots (added/removed elements, text/value, URL/title, new errors) |
| `browser_navigate` | URL (`url`) or history (`action`: back / forward) |
| `browser_force_navigate` | `url`, optional `terminateScripts` — CDP recovery; MCP bypasses gate for this tool |
| `browser_go_back` | History: back |
| `browser_go_forward` | History: forward |
| `browser_click` | Click element (left/right/middle, single/double); locators include `byText` |
| `browser_type` | Type into input (clears first). Content: `value` **or** `text`; locator: `ref` / `byText` / … (not `text`) |
| `browser_upload` | File input: `path`, `paths`, or `base64` + optional `fileName`; optional `submit` (blocked in safe mode) |
| `browser_select_option` | Select dropdown option |
| `browser_hover` | Hover over element |
| `browser_press_key` | Keyboard key press |
| `browser_scroll` | Scroll page or element into view |
| `browser_take_screenshot` | Screenshot page or element. `purpose: journal` (default) saves + attaches to the journal with no image in the result. `purpose: inspect` returns the image (prefer jpeg). Optional `note`, ref/selector, padding |
| `browser_screenshot_compare` | Visual diff vs saved screenshot path (`GET /api/screenshot` or prior capture) |
| `browser_wait_for_idle` | Wait for network quiet + no CSS animations (`POST /api/wait-for-idle` parity) |
| `browser_text` | Element inner text (pierces shadow DOM) |
| `browser_extract` | Extract structured data from tables/repeating elements |
| `browser_page_text` | All visible page text |
| `browser_page_text_all` | All text nodes including hidden; one line per segment |
| `browser_page_text_screen_reader` | Alt, aria-*, title, SVG title/desc (`[kind]` prefixes) |
| `browser_page_source` | Full HTML source |
| `browser_execute_js` | Run JavaScript (not for fetching JS bundles — use `browser_fetch` `serverSide:true` or `js-audit`) |
| `browser_accessibility` | WCAG audit (axe-core) |
| `browser_tab_order` | Keyboard tab-order verification (real Tab/Shift+Tab) |
| `browser_performance` | Web Vitals measurement |
| `browser_resource_snapshot` | Resource snapshot: JS heap, DOM nodes, listeners, WebSockets (CDP). Optional `rememberBaseline` |
| `browser_resource_compare` | Compare saved baseline to current page after your own actions |
| `browser_resource_probe` | Repeat actions or reloads with GC; findings for heap/listener/DOM growth |
| `browser_security` | Passive security overview (Security Scan quicktest modules) |
| `browser_security_js_libraries` | Retire.js JS library CVE scan |
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
| `browser_monkey_trowser` | Monkey Trowser; optional `scope` for this run only (requires `safetyMode: "active"`) |
| `browser_interrupter` | Fault-injection testing: ranked discovery (default `maxEndpoints` 20), `mergeAttackSurface`, `minRelevanceScore` / `minScore`, sibling-host discovery, customFaults, actions, mutate-response, cooldown (requires `safetyMode: "active"`) |
| `browser_fuzz` | Browser-context request fuzzer: §MARKER§ injection points, built-in payload sets (sqli, xss, ssti, **open-redirect**, etc.), attack types (sniper/battering-ram/pitchfork/cluster-bomb), anomaly detection; use **`redirect: manual`** for open-redirect testing (requires `safetyMode: "active"`) |
| `browser_security_csrf` | CSRF assessment: missing/invalid token tests, Referer bypass, JSON API probes, **SameSite cookie context**, **custom-header simple-request probes** (`safetyMode: "active"`; blocked in safe mode) |
| `browser_security_path_traversal` | Path traversal: **query** mode (fuzz query params from log or `urls`) or **path** mode (`mode`, `basePath`, `pathBases`; requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_ssrf_scan` | SSRF scanner: internal IPs, cloud metadata, protocol handlers, callback probes; discovery, **`endpointHints`**, or request template mode; uses `redirect: manual` on redirect-like params (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_open_redirect_scan` | Open redirect scanner (CWE-601): probes redirect/url/next params with `redirect: manual`, checks Location for off-site redirects; **`endpointHints`** for params without query in URL (requires `safetyMode: "active"`; blocked in safe mode) |
| `browser_security_methods` | HTTP methods testing: probes GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE and flags security issues |
| `browser_security_smuggling` | HTTP Request Smuggling: confirmed = repeated differential 404 (CL.TE/TE.CL canary). Timing / TE / CL-CL / HEADER are notes. Requires `safetyMode: "active"`; blocked in safe mode. |
| `browser_security_host_header` | Host header injection scanner: raw TCP probing for Host override, X-Forwarded-Host, duplicate Host, port manipulation, absolute-URL requests. Detects reflected poisoned host in redirects, links, and body. Auto-discovers reset/invite endpoints from network log. Requires `safetyMode: "active"`; blocked in safe mode. |
| `browser_security_shadow` | Shadow: enable/disable/query ambient continuous analysis |
| `browser_firewall_test` | Client-side firewall testing: active verification of CSP, SRI, iframe sandbox, Permissions-Policy (requires `safetyMode: "active"`) |
| `browser_client_surface` | Client-side triage map (sources, sinks, listeners, `risks` checklist); does not run XS-Leaks/postMessage/XSSI probes (security pack) |
| `browser_security_xssi_scan` | XSSI/JSONP hygiene scan from network log or explicit URLs (requires `safetyMode: "safe"`) |
| `browser_postmessage_audit` | postMessage listener audit + synthetic screen; active mocked attacker-origin proof (requires `safetyMode: "safe"`) |
| `browser_security_xs_leaks` | Cross-site leak differentials via mocked attacker origin (requires `safetyMode: "safe"`; blocked in `--safe`) |
| `browser_dom_flows` | Runtime source→sink→consequence chains; `mode=probe` requires `safetyMode: "active"` |
| `browser_dom_xss_audit` | Orchestrated DOM XSS on current URL (depth quick/standard/deep; requires `safetyMode: "active"`) |
| `browser_security_gadget_chains` | Clobber / client-PP / dom-flow gadget orchestrator (requires `safetyMode: "active"`) |
| `browser_gadget_radar` | Missing-global reads + optional perturbing proto traps |
| `browser_security_client_prototype_pollution` | Client-side PP via URL/hash/postMessage canaries (requires `safetyMode: "active"`) |
| `browser_trace_input` | Input→Network→DOM tracing: sources `form`, `url-query`, `url-hash`, `url-path`, `post-message`, `storage`, `window-name`, `referrer`; auto URL probes when form filters input (`probeUrlSources`); `autoBypass`; `monitorSinks` (requires `safetyMode: "active"`) |
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
| `browser_race_lab_profiles` | Race Lab presets: list/save/export/import profiles |
| `browser_race_lab_synchronize` | Race Lab latency compensation (RTT + dispatch offsets) |
| `browser_race_lab_baseline` | Race Lab soft baseline pass |
| `browser_race_lab_run` | Race Lab full run: sync → baseline → burst (`session`: `all-peers`/`driver`/peer; `role`: `observe`/`mutate`/`check`; requires `safetyMode: "active"`) |
| `browser_security_captcha_replay_scan` | CAPTCHA token replay / broken anti-automation (requires `safetyMode: "active"`) |
| `browser_security_rate_limit_audit` | A12 rate-limit audit: sequential + burst, emits missing/weak/present (requires `safetyMode: "active"`) |
| `browser_security_redos_scan` | ReDoS timing oracle on injectable params (requires `safetyMode: "active"`) |
| `browser_security_body_size_limit_scan` | Body-size tiers 1 KB–1 MB on POST endpoints (requires `safetyMode: "active"`) |
| `browser_security_costly_operations` | Single-request cost risks from traffic/DOM (default `safetyMode: "passive"`; optional bounded confirms) |
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
| `browser_fetch_raw` | HTTP/1.x raw TCP/TLS send (TE/CL/duplicates; security pack; blocked in `--safe`) |
| `browser_header_overrides` | Session WebView2 header overrides (get/set/clear; browsing only) |
| `browser_mock` | Manage network mocks |
| `browser_intercept` | Manage request breakpoints |
| `browser_webmcp_tools` | Detect WebMCP tools |
| `browser_webmcp_call` | Call WebMCP tool |
| `browser_network_throttle` | Simulate slow network |
| `browser_wait_for_network` | Wait for specific network request |
| `browser_storage` | Read/write localStorage/sessionStorage |
| `browser_inspiration` | Get a random testing inspiration message |
| `browser_coverage` | Reflective coverage lens (REST: `GET /api/coverage`) — pages visited, interactive elements exercised, and which quality characteristics have been touched, derived from the journal |
| `browser_journal_add` | Add a note to the test journal (observations, bugs, strategy). Supports `evidence`, `tags`, and auto-captures page `url`. |
| `browser_journal_get` | Get journal entries (`since`, `last`, `type`, `source`, `origin`, `evidence`, `tag`, `q`, `view`, `indexes`). Defaults to `view=index` when journal > 40 entries. |
| `browser_journal_update` | Update an existing journal entry by `index` (partial fields, including `evidence`). |
| `browser_journal_delete` | Delete a journal entry by `index`. |
| `browser_compact` | **Built-in assistant only.** Queue conversation compact after journaling a segment (`summary`, `openThreads`, `nextSteps`, `journalIndexes`, `keepLastTurns`). |
| `browser_session_memory` | **Built-in assistant only.** Read/update volatile focus and tasks (`action`: get / set_focus / add_task / update_task). |
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
