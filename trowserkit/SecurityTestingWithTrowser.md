# Security Testing with Trowser — Methodology Guide

A concise guide for AI-driven and manual security testing using the Trowser REST API. You will also have the Trowser API reference (`trowser-api-reference.md`) and endpoint index (`trowser-api-index.md`); this guide focuses on **methodology, patterns, and gotchas** rather than repeating API docs.

---

## Playbooks first, this guide second

Trowser ships **security playbooks** — orchestrated scanners aligned with the Trowser Twelve taxonomy (OWASP Top Ten Extended). Each playbook runs a curated chain of primitives in the right order, applies a uniform `safetyMode`, correlates findings, and returns `nextActions` plus suggested proofs.

### Recommended workflow (fast, focused)

**Browse manually, then scan with `crawl: false`.** Playbooks default to `crawl: false` so they analyze traffic you already captured instead of spending budget on an automatic crawl.

1. Complete **Phase 0 — Setup** (below).
2. **Browse key flows** (login, search, CRUD, checkout) — 5–10 pages or the flows you care about — to populate the network log.
3. Run a playbook with **`"crawl": false`** (the default). For injection and other probe-heavy playbooks, set **`scope.targetUrl`** to one captured endpoint, or use **`depth: "deep"`** only when you explicitly want broader endpoint coverage.
4. Triage the report: severities, `nextActions`, partial attack chains.
5. Use the **sections below** (and Track B checklist items) to prove, deepen, or manually test what the playbooks surfaced.

Set **`"crawl": true`** only when you have not browsed yet and want the playbook to auto-discover links/forms on `scope.host` before scanning. Crawl and probe selection default to **`scope.excludeLogout: true`** (skip logout/sign-out/SLO URLs) so an auto-crawl does not end the session; add **`scope.excludePaths`** / **`excludeUrlPatterns`** for other pages you must not touch. Intentional logout testing still uses **`a07-authn`** / `logout-invalidation-probe` separately.

Preview a playbook's step plan without executing: `POST /api/orchestrate/dry-run/{id}`. List available playbooks: `GET /api/orchestrate/playbooks`. GUI equivalent: Script Console → Quicktests → Security → **Trowser Twelve** (see `QuicktestsForSecurityTesting.md`).

**When to skip playbooks and use this guide directly (depth / full control):**

- SAML / federation deep dives (Phase 4 — not yet a dedicated playbook)
- Custom fuzz templates, intercept/fulfill MITM, dual-session attacks
- Application-specific business logic, creative manual exploration
- Following up on a single finding with precise parameters (trace-input selectors, authz peer diffs, SAML replay variants)
- You already ran playbooks and need the **how-to** for proof, verification, or false-positive triage

Playbooks **wrap** the same REST primitives documented here — they do not replace the patterns and gotchas in the body of this file.

### Playbook → drill-down map

| Playbook ID | Endpoint | Use this guide for follow-up |
|-------------|----------|------------------------------|
| `full` | `POST /api/orchestrate/full` | Phase 4b–4c (chains, proof), Phase 6 (reporting) |
| `quick` | `POST /api/orchestrate/quick` | Default LLM sweep (~60–120s); then `a07-authn` if session testing needed |
| `a01-access` | `POST /api/orchestrate/a01-access` | Authorization Testing (`authz/*`), BAC APIs, IDOR Testing |
| `a02-misconfig` | `POST /api/orchestrate/a02-misconfig` | Phase 2 individual scans, gotchas (discover on SPAs) |
| `a03-supplychain` | `POST /api/orchestrate/a03-supplychain` | Secrets Harvest Methodology |
| `a04-crypto` | `POST /api/orchestrate/a04-crypto` | Secrets Harvest Methodology, session/cookie checks |
| `a05-injection` | `POST /api/orchestrate/a05-injection` | XSS Testing, Fuzzing, Injection Testing |
| `a06-design` | `POST /api/orchestrate/a06-design` | Business logic, race conditions (Phase 3 & 5) |
| `a07-authn` | `POST /api/orchestrate/a07-authn` | Brute-Force / Account Lockout, session testing |
| `a09-opsec` | `POST /api/orchestrate/a09-opsec` | Forced-error interpretation, log-leak triage |
| `a11-ssrf` | `POST /api/orchestrate/a11-ssrf` | SSRF follow-up with custom payloads |
| `a12-availability` | `POST /api/orchestrate/a12-availability` | Load-test / race patterns (Phase 5) |
| `a13-llm` | `POST /api/orchestrate/a13-llm` | LLM output→sink tracing, prompt-injection proof |
| `a14-other` | `POST /api/orchestrate/a14-other` | Smuggling, host-header, open redirect (Phase 5) |
| *(none)* | — | **Phase 4 — SAML / Federation** (manual-first) |

Common playbook request envelope:

```json
{
  "scope": {
    "host": "example.com",
    "targetUrl": "https://example.com/api/search?q=test"
  },
  "safetyMode": "safe",
  "depth": "standard",
  "crawl": false,
  "budget": { "maxSeconds": 120, "maxRequests": 800 },
  "emitSuggestedProofs": true
}
```

Use `"safetyMode": "active"` when injection, fuzz, smuggling, or other live probes are required. See the API reference orchestration section for full options.

---

## Quick-Start Checklist

Two tracks share **Phase 0**. Most sessions should use **Track A** for coverage, then **Track B** (or the detailed sections below) for follow-up.

### Phase 0 — Setup (both tracks)
- [ ] Verify connection: `GET /api/ping`
- [ ] Set headers: `$h = @{Authorization="Bearer <key>"; "Content-Type"="application/json"}`
- [ ] Navigate to target
- [ ] Fill fields with **`POST /api/type`** (there is **no `/api/fill`** — `/api/type` clears first; use `"append": true` to append)
- [ ] Enable shadow mode: `POST /api/security/shadow {"enabled":true,"suggestions":true}`
- [ ] Start OOB callback detection: `POST /api/security/callbacks {"mode":"start"}`
- [ ] (Optional) Start journal for tracking findings

### Track A — Orchestrated sweep (recommended default)

Run after Phase 0 and **manual browsing** (playbooks default to `crawl: false`).

- [ ] Browse key flows to populate the network log (login, search, CRUD)
- [ ] (Optional) Preview steps: `POST /api/orchestrate/dry-run/quick`
- [ ] Run **`POST /api/orchestrate/quick`** with `"crawl": false` for LLM-friendly triage (~60–120s), **or** `POST /api/orchestrate/full` when you need exhaustive coverage
- [ ] Review playbook report: severities, `nextActions`, suggested proofs
- [ ] If SAML/OIDC in scope: run playbook follow-ups or Phase 4 items below
- [ ] Attack chains: playbook `full` correlates cross-category; otherwise Phase 4b items
- [ ] Prove critical findings: Phase 4c (`chain-prove`, verify-workflow, evidence export)
- [ ] Phase 6 — Verification & Reporting

### Track B — Manual primitives & follow-up

Use when playbooks are insufficient, you need full control, or you are **drilling into** playbook findings. Each phase builds on the previous one.

### Phase 1 — Reconnaissance

*Most items covered by playbook crawl + attack-surface steps. Run manually for extra control or when not using playbooks.*

- [ ] Browse 5–10 key pages to populate the network log
- [ ] Map attack surface: `POST /api/security/attack-surface {"includeParameters":true}`
- [ ] Fetch and analyze JS files for dangerous sinks (`eval`, `innerHTML`, `document.write`)
- [ ] Check `document.cookie` via `execute-js` (empty = HttpOnly working)
- [ ] Check response headers via `/api/fetch` (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Identify tech stack: `POST /api/security/tech-stack` (or `browser_security_tech_stack`) — detects servers, frameworks, WAFs, CDNs, JS libraries from headers, cookies, DOM

### Phase 2 — Automated Scans

*Largely covered by `a02-misconfig`, `a03-supplychain`, `a04-crypto`, and `full`. Run individual scans for targeted re-checks.*

- [ ] Run `POST /api/audit-all` for a broad baseline
- [ ] Or run individual scans: `security-headers`, `cookies`, `cors`, `xss`, `mixed-content`, `source-maps`, `storage`, `firewall-test`, `third-party`, `methods`, `discover`, `path-traversal`, `csrf`
- [ ] Run `POST /api/security/auto-scan` — detects SQLi, IDOR (path params), method enumeration, CSRF in one call
- [ ] Run `POST /api/security/secrets-harvest` — finds credentials, tokens, API keys in network responses and JS bundles
- [ ] Check identity state: `GET /api/session/identity` — shows current session info and cookies
- [ ] If SAML: `POST /api/security/saml-decode {"source":"network","findAll":true}`
- [ ] If JWT: `POST /api/security/jwt-analyze {"safetyMode":"active"}`

### Phase 3 — Active Testing

*Core coverage in `a01-access`, `a05-injection`, `a06-design`, `a07-authn`. Use this phase for precision follow-up and business-logic testing.*

- [ ] **Authentication:** brute-force, credential stuffing, account lockout, timing oracle
- [ ] **Authorization (manual):** IDOR via `fetch/batch`, role escalation, cross-tenant access
- [ ] **Authorization (authz APIs):** `authz/diff`, `authz/boundary`, `authz/probe`, `authz/fuzz` (see below)
- [ ] **BAC — ID Harvesting:** `harvest-ids` → feed into `authz/boundary` (see caveats below)
- [ ] **BAC — JWT Sweep:** `jwt-acceptance-sweep` for alg:none + missing-auth on JWT sites
- [ ] **BAC — Auth Bypass Pivot:** `auth-bypass-pivot` with captured bearer token
- [ ] **BAC — REST Scaffold:** `rest-scaffold` for unauthenticated REST API exposure
- [ ] **BAC — Path Filter Bypass:** `path-filter-bypass` for NUL-byte/encoding bypasses (verify findings manually — see gotchas)
- [ ] **Injection:** SQLi, XSS (stored + reflected + DOM), SSTI, LDAP, CRLF, path traversal
- [ ] **CSRF:** Test all state-changing operations with missing/invalid/cross-session tokens
- [ ] **Session:** fixation, cookie tampering, concurrent login behavior
- [ ] **Business logic:** price tampering, negative quantities, mass assignment, pagination abuse

### Phase 4 — SAML / Federation (if applicable)

*No dedicated playbook — manual-first. Essential even after a playbook sweep on federated apps.*

- [ ] Decode and compare assertions across auth methods
- [ ] Test SAML replay (7 variants: plain, cross-SP, identity spoof, sig strip, expired, issuer spoof, combo)
- [ ] Test LOA enforcement (weakest auth → SSO to sensitive SPs)
- [ ] Test SLO propagation and orphaned session survival
- [ ] Test SSO auto-login across all federated SPs

### Phase 4b — Attack Chain Analysis

*Included in `POST /api/orchestrate/full`; run manually after targeted playbooks or custom scans.*

- [ ] Review chain findings: `GET /api/security/chain-findings`
- [ ] List chain patterns: `GET /api/security/chain-patterns`
- [ ] Run chain analysis: `POST /api/security/chain-analyze`
- [ ] Follow partial chain `suggestedAction` leads to fill missing links
- [ ] Add custom chain patterns for application-specific attack paths
- [ ] Re-run `chain-analyze` after new scanners complete

### Phase 4c — Vulnerability Proof & Verification
- [ ] Prove chain findings: `POST /api/security/chain-prove {"safetyMode":"active", "patternId":"<id>"}`
- [ ] Build verify-workflow proofs for critical findings (setup → trigger → oracle → cleanup)
- [ ] Use capture variables to build cross-identity BOLA proofs
- [ ] Export evidence bundles: `POST /api/security/evidence/export {"workflowId":"<id>"}`
- [ ] Rerun proofs after fixes: `POST /api/security/evidence/rerun {"bundlePath":"<path>"}`
- [ ] Export full assessment: `GET /api/vpx/export`

### Phase 5 — Advanced Attacks

*Partial coverage in `a14-other`, `a06-design`, `a12-availability`. Manual items: intercept, interrupter, dual-session, custom fuzz.*

- [ ] MITM simulation via `intercept/fulfill` (response tampering)
- [ ] Fault injection via `interrupter`
- [ ] Race conditions via `fetch/batch {concurrent:true}` or `load-test`
- [ ] Dual-session attacks (if two Trowser instances available)
- [ ] Content-Type confusion, HTTP method override
- [ ] HTTP request smuggling: `POST /api/security/smuggling {"safetyMode":"active"}` (CL-TE, TE-CL, TE-TE, CL-CL)
- [ ] Host header injection: `POST /api/security/host-header {"safetyMode":"active"}` (or `discoverFromNetwork:true` after browsing reset flows)
- [ ] Mass assignment: `POST /api/security/mass-assignment {"safetyMode":"active"}` — test if extra fields in POST/PUT bodies get accepted
- [ ] WAF bypass: `POST /api/security/waf-bypass {"safetyMode":"active"}` — detect and bypass WAF protections
- [ ] GraphQL analysis: `POST /api/security/graphql-analyze {"safetyMode":"active"}` — introspection, depth limits, batch abuse
- [ ] WebSocket audit: `POST /api/security/websocket-audit` — connection auth and message analysis
- [ ] CSWSH test: `POST /api/security/cswsh-test` — Cross-Site WebSocket Hijacking
- [ ] Open redirect, clickjacking

### Phase 6 — Verification & Reporting
- [ ] Confirm all XSS execution via `execute-js`
- [ ] Confirm cookie theft via `document.cookie`
- [ ] Verify MITM chains via `intercept/fulfill`
- [ ] Check shadow mode for passively detected issues
- [ ] Check OOB callbacks
- [ ] Run `chain-prove` on all provable chains
- [ ] Build verify-workflow proofs for critical/high findings
- [ ] Export evidence bundles for reproducible proofs
- [ ] Export VPX assessment package: `GET /api/vpx/export`
- [ ] Export journal and compile severity-rated report
- [ ] On user request, create .trw files for reproduction (json file for api/test-scenario)


---

## Phase 1 — Reconnaissance

### Attack Surface Mapping
Browse the app first (navigate, click, fill forms) to populate the network log, then run:
```
POST /api/security/attack-surface {"includeParameters":true,"includeAuth":true,"includeResponsePatterns":true}
```
Filter by host with `"host":"target.example.com"`. Use the returned request body samples as templates for fuzzing and IDOR testing.

### Technology Stack Discovery
Run in parallel for speed: `/api/security` (CVE/Retire.js), `/api/security-headers`, `/api/third-party`. Fetch and search JS files for `eval(`, `innerHTML`, `document.write(`, `postMessage(`.

### In-Browser Analysis
Use `/api/execute-js` to inspect the page context:
- `document.cookie` — empty means HttpOnly is working
- `document.querySelectorAll('script:not([src])')` — count inline scripts
- `window.__NEXT_DATA__` or `window.__NUXT__` — framework-specific data leaks

---

## Phase 2 — Automated Scans

### All-in-One
`POST /api/audit-all` runs accessibility, performance, security (CVE + XSS + mixed content + source maps), headers, cookies, storage, HTML validation, compatibility, link checking, and GUI consistency.

### Individual Scans Worth Running
| Endpoint | What It Catches |
|----------|----------------|
| `/api/security/xss` | DOM XSS patterns (sinks and sources) |
| `/api/security/cookies` | Missing Secure/SameSite/Path flags (**does not check HttpOnly** — use `document.cookie` for that) |
| `/api/security/cors` | Reflected origins, wildcard misconfig |
| `/api/security/firewall-test` | CSP bypass vectors, SRI, iframe sandbox, Permissions-Policy |
| `/api/security/csrf` | Missing CSRF tokens on state-changing endpoints (**browse and submit forms first!**) |
| `/api/security/discover` | Endpoint brute-force (unreliable on SPAs — see gotchas) |
| `/api/security/path-traversal` | Query-parameter traversal only (path-based requires manual testing) |
| `/api/security/source-maps` | Exposed source maps = full source code disclosure |
| `/api/security/storage` | Sensitive data in localStorage/sessionStorage |

### High-Value Security APIs

These newer APIs provide the deepest security insights and should be run after populating the network log.

**`POST /api/security/auto-scan`** — Composite scanner that detects SQLi, IDOR (path parameters), HTTP method enumeration, CSRF, SSTI, open redirects, and mass assignment from the network log. Returns severity-rated findings. Best run after browsing 5–10 pages.

**`POST /api/security/secrets-harvest`** — Analyzes all captured network responses and JS bundles for credentials, tokens, API keys, and password hashes. Typically finds 20–30 items including hardcoded test credentials. CRITICAL findings include email+password combos in API responses.

**`GET /api/session/identity`** — Returns current session info (cookies, auth state). Replaces deprecated `GET /api/identity`.

### Authorization Testing with `authz/*` APIs

These APIs are the most powerful tools for BOLA/IDOR discovery. They require two identities (either two sessions in the same instance, or two Trowser peers).

| API | Purpose | When to Use |
|-----|---------|-------------|
| `POST /api/authz/diff` | Compare API responses between two identities | First — maps which endpoints leak data across roles |
| `POST /api/authz/boundary` | Test if identity A can access identity B's resources | After diff — confirms IDOR is exploitable |
| `POST /api/authz/probe` | Test which endpoints are accessible to a given identity | Mapping attack surface per role |
| `POST /api/authz/fuzz` | Fuzz parameters with crash detection | After probe — finds input validation gaps |

**Recommended flow:**
1. Log in as admin (T1) and attacker (T2), populate network logs on both
2. `authz/diff` — compare what each identity sees (add `leakTokens` array to detect sensitive data exposure)
3. `authz/boundary` — test unauthorized resource access (add `peer` parameter for cross-session testing)
4. `authz/probe` — map full endpoint access per identity
5. `authz/fuzz` — fuzz parameters on accessible endpoints

### Broken Access Control — New BAC APIs

These newer APIs target specific BAC sub-categories. Run them after populating the network log.

**`POST /api/security/harvest-ids`** — Harvests numeric/GUID/hex IDs from network log and DOM. Read-only (no `safetyMode` required). Returns `ids[]` and `suggestedBoundaryTests[]`.
- Captures IDs from query parameters (e.g., `?productId=1`), reporting `kind`, `value`, `source`, `paramName`, `type`, and `contextUrl`.
- `suggestedBoundaryTests` generates ready-to-use configs for `authz/boundary` with `urlTemplate`, `parameter`, `authorizedValues`, `unauthorizedValues`, and `reason`.
- **Known issue:** `urlTemplate` in suggestions uses URL-encoded `%7bid%7d` instead of `{id}`. Decode before passing to `authz/boundary`.

**`POST /api/security/jwt-acceptance-sweep`** — Sweeps endpoints for missing auth and JWT alg:none acceptance. Best on JWT-authenticated APIs. Requires `safetyMode: "active"`.
- Accepts explicit `token` parameter — use a crafted alg:none JWT to test specific endpoints.
- Returns per-endpoint comparison: `anonStatus`, `jwtNoneStatus`, body hashes, and findings.
- On non-JWT sites, still useful for missing-auth detection across all attack-surface endpoints.

**`POST /api/security/auth-bypass-pivot`** — Captures a bearer token and retests 401/403 endpoints. Requires `safetyMode: "active"`.
- Pass `token` explicitly, or let it auto-discover from `jwt-analyze`.
- With `trySqliLoginBypass: true` and `loginUrl`, attempts multiple SQLi payloads to extract a token.
- Reports per-endpoint: `anonStatus`, `authStatus`, `outcome` (e.g., `STILL_DENIED`, `UNLOCKED`).
- **Tip:** Browse pages that return 401/403 first — the tool auto-detects retest candidates from the network log.

**`POST /api/security/rest-scaffold`** — Probes ~23 common REST paths (`/api/Users`, `/api/products`, `/rest/admin/`, `/api/v1/users`, etc.) without auth. Requires `safetyMode: "active"`. Tests both GET and HEAD for each path.
- Response includes `pathsProbed[]` listing all tested paths and per-request status/method detail.
- Auto-runs in `auto-scan` when captured API endpoints are sparse.

**`POST /api/security/path-filter-bypass`** — NUL-byte, double-encoding, and backslash-normalize bypass probes. Requires `safetyMode: "active"`.
- Accepts `bases` parameter for targeted testing (e.g., `"bases": ["/admin/"]`).
- Default bases include security-relevant paths: `/admin/`, `/api/`, `/internal/`, `/debug/`, `/console/`, `/ftp/`, `/files/`, `/static/`.
- Tests multiple payloads per base: `backslash-normalize` (`/..\`) and `encoded-dot-dot` (`/%2e%2e/`).
- **⚠️ False positive warning:** Traversal findings (e.g., `/admin/..\` → 200) often resolve to the site root via `..` normalization. Verify that the bypass response differs from the homepage content. If body matches `/`, it's URL normalization, not a filter bypass.
- Indicator `content-differential` confirms only that status codes differ — manual content verification is still needed.

**Recommended BAC testing sequence:**
1. Browse 5–10 pages on T1 (authenticated) and T2 (unauthenticated)
2. `harvest-ids` → note discovered IDs
3. `authz/diff` with `peer:"attacker"` → identify BOLA/FILTERED endpoints
4. `authz/boundary` with harvested IDs → test access control boundaries
5. `rest-scaffold` → check for exposed REST API paths
6. `jwt-acceptance-sweep` → check for missing auth (JWT sites)
7. `path-filter-bypass` → test filter bypass (verify findings manually!)
8. `auto-scan` with `includeAuthBypassPivot:true, includePathFilterBypass:true` → composite check

---

## Phase 3 — Active Testing

### XSS Testing

**Reflected XSS** — use `trace-input` with `autoBypass:true` for automatic filter detection and bypass:
```
POST /api/security/trace-input {"target":"#search-input", "submit":"#search-btn", "submitAction":"click", "autoBypass":true, "safetyMode":"active"}
```
Note: `target` and `submit` accept CSS selectors only (not refs). With `autoBypass`, omit `payload`/`payloads` — the tool starts with `<script>alert(1)</script>` and escalates through 10+ alternative vectors if filtered.

**DOM XSS** — use `source:"url-query"` or `source:"url-hash"` to probe URL-sourced DOM XSS. Sink monitoring hooks (`monitorSinks:true`) are installed before navigation, catching `document.write`/`innerHTML`/`eval` calls with full stack traces:
```
POST /api/security/trace-input {"source":"url-query", "queryParam":"default", "autoBypass":true, "monitorSinks":true, "safetyMode":"active"}
POST /api/security/trace-input {"source":"url-hash", "autoBypass":true, "monitorSinks":true, "fragmentEncode":"none", "safetyMode":"active"}
```
For DOM XSS sources, `queryEncode` defaults to `"none"` (raw payload in URL). Use `fragmentEncode:"none"` for hash sources. Always test **both** query and hash vectors — server-side filters may block one but not the other.

**Exploit verification** — confirm XSS with definitive proof via `verify`. Use the two-step workflow: `trace-input` (find candidates) → `verify` (prove execution):
```
POST /api/security/verify {"safetyMode":"active", "renderUrl":"https://target/page?q=<script>window.__xss_proof=1</script>", "skipInjection":true, "effectCheck":"window.__xss_proof === 1", "waitAfterRenderMs":500}
```

**Stored XSS verification pattern:**
1. Submit payload via the app's form/API
2. Navigate to where it renders (may be a different page or user role)
3. Use `execute-js` to check `window.__xss_proof` (async payloads like `onerror` need a `Start-Sleep` before checking)
4. Compare: payload in API response but not in DOM → client-side sanitization; absent from API → server-side sanitization

**XSS payload priority** (most likely to bypass partial sanitization first):
1. `<img src=x onerror="...">` — bypasses `<script>` blocking
2. `<svg onload="...">` — often missed by tag-based filters
3. `<a onmouseover="...">` — event handler on allowed tag
4. `javascript:alert(1)` — in href attributes

### IDOR Testing
Use `/api/fetch/batch` with `concurrent:true` to test many IDs in parallel while keeping the browser session. Test boundary values: `0, -1, 1, 999999, 2147483647, 2147483648`.

Alternatively, use `/api/intercept` + `/api/intercept/continue` with URL modification — more natural for intercepting and modifying live requests.

### Brute-Force / Account Lockout
Three-step pattern:
1. **Sequential wrong passwords** (10–15) to test basic lockout
2. **Concurrent burst** via `fetch/batch` with `concurrent:true` (50 requests) to test rate limiting
3. **Verify correct password still works** — if it does, zero lockout

Use `/api/load-test` for quick server-side concurrency testing (no browser cookies by default).

### Injection Testing

Match XSS depth: prefer a captured **full request** (or form-aware shorthand) over a bare page URL.

**Shorthand vs full `request`:**
```json
{ "safetyMode": "active", "url": "https://app/vuln/?id=1&Submit=Submit", "param": "id" }
```
```json
{
  "safetyMode": "active",
  "request": {
    "url": "https://app/vuln/?id=§id§&Submit=Submit",
    "method": "GET"
  }
}
```
Shorthand `{ url, param }` injects `§param§` and **keeps sibling query keys**. When the current page has a matching GET form, Trowser also clones missing siblings (e.g. `Submit`) from the live DOM. Prefer the full `request` template when you already captured the exact wire request.

**Classic PHP form sinks:** Always preserve non-injected form fields (`Submit`, CSRF tokens, hidden inputs) from a captured request. Example (DVWA SQLi low):
```json
{
  "safetyMode": "active",
  "url": "http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit",
  "param": "id",
  "useBackendFetch": true,
  "includeBrowserCookies": true
}
```
Omitting `Submit=Submit` often yields a silent false negative (identical empty form page for every payload).

**Boolean proof interpretation:**
- `blind-boolean-suspected` — response diverged from baseline on a tautology-looking payload (heuristic).
- `blind-boolean-confirmed` — a configured truthy/falsy pair (`1 AND 1=1` vs `1 AND 1=2`, including `--` variants) produced **different** noise-stripped bodies **after neutralizing payload echo**, with a content oracle (one side near the successful baseline). Equal stripped bodies, shared CSRF-fail clusters, or CSRF-rejected baselines → not confirmed. GET forms with CSRF query tokens refresh the token per probe.
- **MySQL coercion FP note:** pairs that only differ because the payload string is reflected in a form `value=` attribute are **not** confirmed. Prefer error-based signatures or a clear content oracle (row present vs absent) before claiming blind boolean SQLi.

**False-negative checklist** (after a “clean” injection / redirect scan):
1. Missing `Submit` / sibling form fields / CSRF token in the probe
2. Wrong encoding (marker percent-encoded; PowerShell mangled `§`)
3. Cookies not sent — retry with `useBackendFetch` + `includeBrowserCookies`, or stay on an authenticated page for in-browser fetch
4. Open redirect: used default redirect-follow instead of `"redirect": "manual"` / `open-redirect-scan`
5. Open redirect: only scaffolds probed — pass `urls` / `endpointHints` and check `warnings` / `verbose` trace
6. Refs stale after navigation — re-`/api/state` before form fills

### Fuzzing
Use `POST /api/fuzz` with `§PAYLOAD§` markers and built-in payload sets: `xss-basic`, `sqli-basic`, `ssti`, `path-traversal`, `auth-bypass`, `json-breaking`, `header-injection`, `xxe`, `ssrf`, and more. Prefer `sniper` attack type — `pitchfork` with large payload sets can hang.

### CSRF Validation
The scanner only detects endpoints with explicit CSRF tokens. For apps without tokens (e.g., cookie-only auth), test manually: send state-changing requests without any CSRF token via `/api/fetch`. Also test GET-based state changes.

Always test three scenarios: missing token, invalid token, token from a different session.

---

## Phase 4 — SAML / Federation Testing

### Decode SAML Messages
```
POST /api/security/saml-decode {"source":"network","findAll":true}
```
Or decode specific messages: `{"samlMessage":"<base64>","messageType":"response"}`.

### SAML Replay Attacks
Use `/api/security/saml-replay`. **Key field names** (differ from what you might guess):
- `targetUrl` — the SP's ACS endpoint (not `acsUrl`)
- `assertion` — the captured SAML assertion (Base64)
- Boolean flags: `removeSignature`, `changeSubject`, `removeAudienceRestriction`, `changeIssuer`, `expireAssertion`

**Seven attack variants to test:** plain replay, cross-SP replay, identity spoofing, signature stripping, expired assertion, issuer spoofing, and full combo (strip sig + change subject + remove audience).

**Known Trowser issue:** The `responseStatus` field in replay results is always empty.

### LOA Enforcement
Authenticate with the weakest method (e.g., password-only = LOA_0), then SSO to SPs that handle sensitive data. If SSO succeeds, the SP isn't enforcing minimum LOA. Decode the assertion to confirm `AuthnContextClassRef` shows the weak LOA.

### SLO Testing
Test both completed flows (assertion consumed) and **orphaned flows** (assertion never consumed). They may behave differently during SLO. After SLO completes, test if the IdP session is still alive by calling a session-bound endpoint.

**Critical pattern:** Login → skip identity-response → SLO from another SP → check if orphaned session survived.

### SSO Federation Verification
After authenticating at one SP, navigate to every other SP in the federation. If the URL stays at the SP (not redirected to IdP login), SSO worked. Compare SAML assertions across auth methods — verify NameIDs, attributes, signing algorithms, and LOA are correct.

---

## Phase 5 — Session & Authentication Testing

### Cookie Analysis
- `/api/cookies` — read all cookies (including HttpOnly ones not visible to JS)
- `/api/cookies/set` — set forged cookies to test server-side validation
- `/api/cookies/delete` — delete cookies to test session behavior
- `document.cookie` via `execute-js` — cross-check what JS can access

**Cookie validation test:** Forge the session cookie with a fake value. If the session dies (e.g., 412) → server validates cookies (good). If the session continues → cookie is decorative (bad).

### Session Fixation
Fabricate session IDs and test if the server accepts them. Use various formats: all-zeros, too-short, non-hex characters, empty.

### Timing Oracle / User Enumeration
Compare response timing for valid vs invalid user identifiers. Use `[System.Diagnostics.Stopwatch]` around `/api/fetch` calls. If timing varies significantly (>100ms), you have an oracle.

### Duplicate JSON Key
Jackson-based backends may crash on duplicate keys. Test: `{"field":"a","field":"b"}` — if it returns 500 with a Java class name, that's an info leak.

---

## Phase 6 — Advanced Attacks

### MITM Simulation via Intercept
`POST /api/intercept` → `POST /api/intercept/fulfill` is the most powerful technique for simulating man-in-the-middle attacks.

Pattern: set breakpoint → trigger request → inspect pending → fulfill with modified response → verify effect in DOM.

**Critical:** Intercept blocks the request until fulfilled. Always clear rules after testing with `/api/intercept/clear`.

### Fault Injection
`POST /api/interrupter` systematically tests error handling. Faults: `server-error`, `empty-body`, `invalid-json`, `slow-response`, `mutate-response`. Use the `url` parameter to target specific endpoints — auto-discovery misses SPA endpoints.

### Race Conditions
Use `/api/fetch/batch` with `concurrent:true` or `/api/load-test` with `concurrency:N`. Look for: mixed status codes, duplicate resource creation, stack traces.

For atomic operations (e.g., consume-once tokens), send 10 concurrent requests and verify exactly 1 succeeds.

### Content-Type Confusion
Test how the server handles unexpected Content-Types: `application/xml`, `text/xml`, `multipart/form-data` (without boundary), `multipart/mixed`, `application/x-java-serialized-object`. Many servers return 500 instead of 415, leaking parser info.

### Host Header Injection
`POST /api/security/host-header` tests 7 probe types via raw TCP (bypassing browser Host header restrictions):

```
POST /api/security/host-header {"safetyMode":"active", "url":"https://target.com/forgot-password", "method":"POST", "body":"email=victim@test.com"}
```

**Best practices:**
- Start with `"discoverFromNetwork":true` after browsing password-reset, invite, and recovery flows. The scanner auto-discovers these endpoints from the network log.
- For manual targets, test POST endpoints that trigger emails (forgot-password, invite-user, change-email) — these are the highest-impact targets for host header poisoning.
- Use `"includeBrowserCookies":true` (default) for authenticated endpoints; set to `false` for unauthenticated baseline testing.
- Test with a custom `evilHost` matching your callback infrastructure for real-world verification.
- All 7 probe types: `host-override`, `x-forwarded-host`, `x-original-host`, `forwarded`, `duplicate-host`, `host-port`, `absolute-url`. Use `probes:["all"]` for comprehensive testing.
- Check `rawRequest` in probe results for manual reproduction in tools like Burp Repeater.

### SSRF Scanning
`POST /api/security/ssrf-scan` has two modes: **discovery** (scans network log for URL-like parameters) and **template** (inject `§ssrf§` markers into custom requests).

**Discovery mode** (after browsing):
```
POST /api/security/ssrf-scan {"safetyMode":"active"}
```
Finds parameters named `url`, `redirect`, `callback`, `webhook`, etc. from captured traffic.

**Template mode** (targeted):
```
POST /api/security/ssrf-scan {"safetyMode":"active", "request":{"url":"https://target.com/api/proxy?url=§ssrf§", "method":"GET"}}
```

**Best practices:**
- Browse extensively first — discovery mode only finds parameters already in the network log.
- For XML endpoints, test XXE manually (the SSRF scanner does not inject XML entity payloads).
- Use `includeCallbackProbes:true` with `POST /api/security/callbacks {"mode":"start"}` for OOB detection.
- Custom payloads via `"payloads":["http://169.254.169.254/","http://internal:8080/"]` for targeted internal service scanning.
- Set `includeInternalIps`, `includeProtocolHandlers`, `includeCallbackProbes` to `false` individually to isolate which payload class triggers findings.

**Gotchas:**
- Discovery mode requires URL-like parameters in the network log — endpoints using XML, GraphQL, or non-standard body formats are missed. Test those manually or with the fuzzer.

---

## Dual-Session Testing

Two separate Trowser instances provide genuine browser-level isolation (independent cookie jars, sessions, storage). This enables attack scenarios impossible with a single browser. If this is worthwhile, ask the user to setup two Trowser instances from two different Trowser.exe.

**Setup:**
```powershell
$h1 = @{Authorization="Bearer <key1>"; "Content-Type"="application/json"}  # port 6923 (victim)
$h2 = @{Authorization="Bearer <key2>"; "Content-Type"="application/json"}  # port 6924 (attacker)
```

### Peer Registration

Register the peer so APIs like `peer/fetch`, `authz/boundary`, and `authz/diff` can operate cross-session:
```powershell
Invoke-RestMethod -Uri "http://localhost:6923/api/peer/register" -Method POST -Headers $h1 -Body (@{
    name="attacker"; baseUrl="http://localhost:6924"; apiKey="attacker-key"
} | ConvertTo-Json)
```

### `peer/fetch` — Cross-Session Request Execution

The most powerful dual-mode primitive. Executes a request through the peer's browser context:
```powershell
# Attacker fetches admin's data through T1's browser (with T1's cookies/tokens)
Invoke-RestMethod -Uri "http://localhost:6924/api/peer/fetch" -Method POST -Headers $h2 -Body (@{
    peer="admin"; url="https://target.com/api/users"; method="GET"
    headers=@{"Authorization"="Bearer $adminToken"}
} | ConvertTo-Json -Depth 5)
```

**Use cases:**
- Token theft: use admin's JWT from attacker's session
- Cross-session IDOR: access victim's resources through victim's browser
- Stored XSS injection: submit payloads through victim's session
- Data exfiltration: pull sensitive data back to attacker's context

### Attack Patterns

| Attack | What to Test | How |
|--------|-------------|-----|
| **Cross-session token theft** | Can T2 consume T1's auth token/response? | T2 uses T1's identity-response URL via `fetch` |
| **Cross-session login** | Can T2 login on T1's session? | T2 sends login with T1's session ID in headers |
| **Cookie swap** | Can stolen cookies hijack a session? | Extract T1's cookies, inject into T2's requests |
| **SLO isolation** | Does T1's logout affect T2? | T1 logs out → check if T2 is still authenticated |
| **Simultaneous SLO** | Race condition in SLO processing? | Both click logout at the same time (use `Start-Job`) |
| **Concurrent brute-force** | Rate limiting across sessions? | T1 and T2 both send wrong passwords for same user |
| **XSRF token swap** | Are CSRF tokens bound to session? | T2 uses T1's XSRF-TOKEN in requests |
| **Concurrent same-user login** | Session collision? | T1 and T2 both login as same user simultaneously |
| **SAML replay cross-session** | Can T2 replay T1's assertion? | Capture T1's assertion, replay from T2 via `saml-replay` |
| **`authz/diff` cross-identity** | BOLA discovery across roles | Run `authz/diff` with both identities — flags endpoints returning different data |
| **`authz/boundary` via peer** | Unauthorized access through peer | Add `"peer":"attacker"` to run boundary tests through T2's session |

### Key Insight: Check Victim Impact
When T2's attack returns 403/412 (defended), always verify that **T1's session was not destroyed** by the attack. Some implementations destroy the victim's session as a side effect of rejecting the attacker.

---

## Gotchas & API Quirks

### `/api/fetch` — Same-Origin Cookie Requirement
`/api/fetch` runs `fetch()` inside the browser. For cookies to be sent, the browser must be on the **same origin** as the target URL. Navigate there first with `/api/navigate`, then use `/api/fetch`.

### `/api/fetch` — Headers Are an Object
The response `data.headers` is a key-value object, not an array:
```powershell
$csp = $r.data.headers."content-security-policy"    # ✅ Correct
# $r.data.headers | Where-Object { $_.name -eq "csp" }  # ❌ Wrong
```

### `/api/fetch/batch` — Response Field Name
The response field is `results`, not `responses`.

### `/api/load-test` vs `/api/fetch/batch`
- `load-test`: server-side, no browser cookies by default (use `useBrowserCookies:true`). Best for quick concurrency checks.
- `fetch/batch`: browser-context, includes cookies and session. Best for authenticated concurrent testing.

### `/api/fuzz` — Can Hang
Large payload sets with `pitchfork` attack type can run 4+ minutes without progress. Use `/api/abort` to recover. Prefer `/api/fetch/batch` for controlled parallel testing.

### `/api/security/discover` — Unreliable on SPAs
SPAs with catch-all routes return 200 for every path. Compare response body sizes — identical sizes mean the catch-all page. Use network log analysis for real endpoint discovery instead.

### `/api/security/cookies` — Does Not Check HttpOnly
Always supplement with `document.cookie` via `execute-js`.

### `/api/security/csrf` — Needs Network History
Browse and submit forms first. The scanner only checks POST/PUT/PATCH/DELETE requests already in the network log. It won't detect GET-based state changes — test those manually.

### `/api/security/methods` — Misleading with SSO
Server-side methods testing doesn't carry browser cookies. 302 redirects to login may be counted as "allowed". Validate findings with authenticated `/api/fetch`.

### `/api/click` — Stale Refs After Navigation
After any navigation (including SAML SSO redirects), element refs become invalid. Use `byText` selectors instead of `ref` numbers.

### `/api/execute-js` — Field name, Promises, and fetch()
Body field is **`script`** (not `expression`). `ExecuteJs` **awaits Promises** — async IIFEs and `.then()` chains return their resolved value. For HTTP probes, prefer **`/api/fetch`** or **`browser_fetch`**: structured status/headers/body and entries in the network log. Raw `fetch()` inside execute-js works when wrapped in an async expression, but ad-hoc fetches are not logged in `browser_network`. In Angular SPAs with Zone.js, **`browser_fetch`** is still safer than manual fetch in execute-js.

### Hidden injection surfaces (do not stop at observed params)
Captured traffic often uses one query key while the sink also accepts siblings. Before declaring “no SQLi/SSTI”:

- Fuzz sibling query names: `query`, `q`, `search`, `id`, `count`, `filter`, `term`, `keyword`, `dummy`, `maptitle`
- Probe a small header set when relevant: `x-product-name`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`
- For SSTI, try a **Content-Type matrix** (`text/plain`, `application/json`, `application/x-www-form-urlencoded`) — JSON-only traffic frequently misses engines that evaluate plain text
- Auto-scan now mutates common sibling query names; still run **one** targeted `sqli-scan` / `trace-input` / `ssti-scan` per high-value endpoint before closing

### Open redirect — use `redirect: "manual"`
Do **not** conclude open-redirect miss from browser `fetch` with default follow (you lose the `Location` header). Use `POST /api/fetch` with `"redirect": "manual"` or `open-redirect-scan`. Explicit `urls` / `endpointHints` / DOM redirect links outrank scaffold paths (`/api/goto?url=` style). When hints are set, scaffolds are skipped unless `includeScaffoldWithExplicit: true`. If the response includes `warnings` that a hint was not probed, treat the scan as incomplete.

Working reproduction (prefer over scaffold-only runs):
```json
{
  "safetyMode": "active",
  "verbose": true,
  "urls": ["https://app/redirect/low.php?redirect=info.php"],
  "maxCandidates": 5
}
```
or
```json
{
  "safetyMode": "active",
  "endpointHints": [{ "url": "https://app/redirect/low.php", "paramNames": ["redirect"] }]
}
```

### `/api/abort` and composite scanners
`POST /api/abort` cancels the gated operation’s `OperationCancellation` token. **auto-scan** and nested injection scanners check that token between probes and should unwind. Guarantees are **checkpoint-based** (not a hard kill of an in-flight socket). If the gate stays busy for minutes after abort, the current nested call may be ignoring cancellation — force-navigate / restart the instance as a last resort.

### Severity policy for agents (HIGH/CRITICAL)
Treat **HIGH/CRITICAL** as “needs proof” until corroborated:

| Class | Require before CRITICAL |
|-------|-------------------------|
| XSS | Sink reach **or** reflection + causal Dom — not residual markers alone |
| Command injection | Shell-output canary (`cmd-canary`), not SQLi differentials on `cmd`/`exec` |
| File upload | Persistence / readback oracle — HTTP 200 on multipart to a render/SSTI sink is **not** upload RCE |
| SQLi | Error signature, confirmed boolean pair, or auth-bypass heuristic — not a single length delta; use collapsed `findings` + `details.findingGroups` (payload catalogs), not one alert per payload |

When cmd-canary and SQLi both fire on the same parameter, **keep RCE** and drop the SQLi finding (class arbitration).

### False-positive triage checklist

Short checks before filing HIGH/CRITICAL from Trowser scanners.

#### Residual DOM (trace-input / XSS)

**Symptom:** `verdict: critical` / “Confirmed DOM XSS” while `payloadReachedSink: false`, `payloadReflected: false`, and often HTTP 404 (url-query fallback after form filtering).

**Cause:** Prior stored/reflected probes left `onerror` / markup in the page; Dom markers matched ambient content for a *different* probe.

**Triage:**

1. Ignore CRITICAL when `payloadReachedSink: false` **and** no reflection for *this* payload.
2. Prefer `info` / residual wording in `verdict.summary` — do not file as confirmed XSS.
3. Re-test on a clean session or after clearing stored comments; require sink hit or reflection before escalating.

API behavior: severity is capped to **info** for residual markers; Dom.Dangerous is reconciled away on error statuses without sink/reflection.

#### Echo-boolean SQLi

**Symptom:** Many “blind boolean” highs that differ only because the form echoes the payload string (`1 AND 1=1` vs `1 AND 1=2`).

**Triage:**

1. Prefer `blind-boolean-confirmed` (noise-stripped hash split after payload-echo neutralization) or SQL error signatures.
2. Treat length-only differentials without confirmation as tentative.
3. Use `details.findingGroups` / `extra.payloads` — one group per `(endpoint, param, class)`, not one finding per payload.

#### Wrong-difficulty / wrong-method URL

**Symptom:** Scanner probes GET `?id=` while the live form is POST (or the opposite difficulty path on lab apps).

**Triage:**

1. Snapshot the live form / `attack-surface` first; use cloned sibling fields (`FormProbeCloner` / `{ url, param }` shorthand).
2. A 404 or CSRF rejection on every payload is **inconclusive**, not “safe”.
3. Do not treat homepage body equality after traversal as a bypass (see path-filter-bypass notes below).

#### Auto-scan hung / partial

**Symptom:** Gate stays `busy` for many minutes on `scanDepth: quick`.

**Triage:** `maxStepSeconds` defaults apply (quick≈120s, standard≈300s, thorough≈900s). On expiry expect `budgetExhausted: true` and partial findings — not a hang. Use `POST /api/abort` if a nested call ignores cancellation mid-socket.

### `sqli-scan` shorthand and PowerShell markers
`{ "url", "param" }` injects literal `§param§` into the query and retains sibling query params already on the URL. When a matching GET form is on the current page, missing siblings (including submit buttons) are cloned from the DOM. In PowerShell prefer `{{param}}` inside a full `request.url`, or JSON `\u00A7param\u00A7`. Never hand-build markers through `UriBuilder` — percent-encoding breaks marker detection.

### `trace-input` response shape
Auto-bypass responses expose **`verdict`** (alias of `worstVerdict`) plus `effectiveTrace.verdict`. Do not treat a missing top-level `verdict` on older builds as “null finding” — read `worstVerdict` / `effectiveTrace`.

### Playbook / auto-scan budgets
Standalone **`auto-scan`** applies a depth default wall-clock budget (`quick`≈120s, `standard`≈300s, `thorough`≈900s) via `maxStepSeconds` when omitted — expect `budgetExhausted: true` and partial results rather than an indefinite busy gate. `a05-injection` recommends ~1800s. With `budget.honorRequested=true` and a short cap (e.g. 90s), the playbook switches to an **injection-fast** profile and cancels in-flight scanners at the step timeout. Prefer `depth: "quick"` or raise `budget.maxSeconds`.

### `/api/clear-all` — Destructive
Clears form fields and configuration. Never call on an SP config page without the `preserve` parameter.

### PowerShell `ConvertTo-Json`
Default depth is 2. Always use `-Depth 5` or higher for nested request bodies. For journal entries, raw JSON strings work more reliably than `ConvertTo-Json`.

### `/api/security/path-filter-bypass` — False Positives with Traversal Payloads
The `backslash-normalize` and `encoded-dot-dot` payloads (e.g., `/admin/..\`) resolve to the site root via URL normalization, producing a status change (403→200 or 404→200) that may not be a real bypass. Always verify: fetch the bypass URL and compare the response body against `/` — if they match, it's a false positive. The `content-differential` indicator confirms only a status difference, not that different protected content was accessed.

### `/api/security/harvest-ids` — URL-Encoded Placeholders in Pipeline
The `suggestedBoundaryTests[].urlTemplate` emits `%7bid%7d` instead of `{id}`. When feeding suggestions directly into `authz/boundary`, decode the placeholder first: replace `%7b` → `{` and `%7d` → `}`. Without this, the boundary test will fail with status=0 errors on all unauthorized values.

### `/api/security/auth-bypass-pivot` — Requires 401/403 in Network Log
The tool auto-detects retest candidates from the network log. If you haven't browsed any pages that return 401/403, it reports `endpointsRetested: 0`. Browse protected endpoints first (e.g., navigate to `/admin`).

### `/api/authz/boundary` — Field Names
Use `authorizedValues` / `unauthorizedValues` (not `authorizedIds` / `unauthorizedIds`). The `parameter` field is required alongside `endpoint`.

---

## Testing Patterns

### 500 Error Hunting
APIs often return 500 for: missing required params, boundary values (0, -1, MAX_INT), empty POST bodies, invalid enums, special characters in paths. Watch for stack traces, class names, SQL errors, and internal architecture leaks in 500 responses.

### Progressive Field Discovery via NPE Chains
When a POST endpoint returns 500 with `NullPointerException` mentioning field X, supply X and see if a new NPE reveals field Y. Compare discovered field names with what the frontend sends — mismatches reveal backend mapping bugs.

### Authorization Ordering Analysis
Test the same operation across multiple endpoints. If some return 403 (auth check first) and others return 500 (null check first), the 500 endpoint may have an authorization bypass — it processes input before checking permissions.

### Enumeration Oracles
Compare status codes, response bodies, and timing for existing vs non-existing resources. Even with identical error messages, timing differences can serve as a side channel.

### Attack Chain Thinking
The highest-impact findings come from chaining:
- **CSRF + Stored XSS** = self-propagating worm
- **File upload + missing HttpOnly** = account takeover via cookie theft
- **Error page reflection + phishing** = credential theft with legitimate-looking domain
- **IDOR + missing auth ordering** = data access without authentication

### Attack Chain Engine (Automated Chain Discovery)

Trowser's Attack Chain Engine (`chain-analyze`, `chain-findings`, `chain-patterns`) automates the discovery of multi-step attack chains where individually low/medium findings combine into critical exploits. Use it after populating findings via shadow mode and automated scans.

**Recommended workflow:**

1. **Populate findings** — Run shadow mode + `auto-scan` + `audit-all` + individual scanners to generate a broad finding set.
2. **List available findings** — `GET /api/security/chain-findings` shows all findings normalized for chaining. Use `?category=xss` to filter.
3. **Review built-in patterns** — `GET /api/security/chain-patterns` lists the 17 built-in chain patterns (e.g., CSRF→XSS worm, CORS+info leak→token theft).
4. **Run chain analysis** — `POST /api/security/chain-analyze` matches findings against all patterns and returns:
   - **Confirmed chains** — all required findings present, with severity upgrade, narrative, and confidence score
   - **Partial chains** — some findings present, with `missingCategories` and `suggestedAction` telling you exactly what to test next
5. **Follow partial chain leads** — Each partial chain includes a `suggestedAction` (e.g., "POST /api/security/csrf — check state-changing endpoints") that tells you which scanner to run to confirm or rule out the chain.
6. **Add custom patterns** — `POST /api/security/chain-patterns` with `action:"add"` to define application-specific chains:
   ```json
   {
     "action": "add",
     "id": "ssti-missing-csp-xss",
     "name": "AngularJS SSTI + Missing CSP → Code Execution",
     "severity": "critical",
     "impact": "arbitrary-code-execution",
     "categories": ["xss", "missing-csp"]
   }
   ```
7. **Re-analyze** — After adding custom patterns or running more scanners, re-run `chain-analyze` for updated results.

**Key benefits:**
- **Severity escalation** — a medium XSS + medium missing-CSP automatically escalates to a high/critical chain finding
- **Guided testing** — partial chains tell you exactly what's missing, reducing wasted effort
- **Custom patterns** — encode your domain knowledge (e.g., "prototype pollution + DOM sink → XSS") into reusable patterns
- **Narrative generation** — each chain includes a human-readable explanation of the attack path

**Gotchas:**
- Chain analysis only works with findings from shadow mode and automated scanners (findings in `chain-findings`). Manual findings from `fetch`/`execute-js` are not automatically included. Use `POST /api/security/chain-findings` to add custom findings.
- Run `chain-analyze` iteratively — after each new scanner completes, re-run to discover newly completable chains.
- The `confidenceScore` reflects whether findings are from the same endpoint/page or different parts of the application.

### Chain-Prove (Automated Proof Execution)

Once `chain-analyze` identifies provable chains, use `chain-prove` to automatically execute proof workflows:

```
POST /api/security/chain-prove {"safetyMode":"active", "patternId":"missing-csp-reflected-xss"}
```

**How it works:**
1. The engine looks up the chain pattern's proof template
2. Substitutes `{{endpoint}}`, `{{payload}}`, and other variables from matched findings
3. Executes a multi-step workflow: setup (identity) → trigger (inject/fetch) → oracle (effectCheck/fetch)
4. Returns `proven: true/false` with per-step evidence

**Reading results:**
- `steps[]` — each step includes `description`, `succeeded`, `evidence`, `error`, and `elapsedMs`
- `templateExpanded` — the full workflow JSON after variable substitution (invaluable for debugging)
- `failureReason` — structured array of step failures with phase, type, and evidence
- If prerequisites are missing (e.g., identity not captured), errors are actionable: `"Identity 'attacker' not found. Capture it first with POST /api/identity/capture."`

**Best practices:**
- Check `chain-analyze` results for `provable: true` chains before running `chain-prove`
- Capture required identities first (e.g., `admin`, `attacker`) — many chain patterns require multi-identity workflows
- Even when `proven: false`, the `templateExpanded` and step evidence are useful for manual follow-up
- Chain-prove that "fails" due to server-side sanitization (e.g., Angular blocking XSS) is still a valid test result — it confirms the defense works

### Verify-Workflow (Custom Proof Workflows)

`POST /api/security/verify-workflow` is the most powerful proof primitive. It defines a multi-phase workflow: **setup → trigger → oracle → cleanup**, where each phase can contain multiple steps.

**Basic pattern — prove SQLi with fetch oracle:**
```json
{
  "safetyMode": "active",
  "name": "sqli-proof",
  "trigger": [{
    "type": "fetch",
    "url": "https://target/search?q=' OR 1=1--",
    "method": "GET"
  }],
  "oracle": {
    "type": "fetch",
    "lastTrigger": true,
    "expect": { "status": 500 }
  }
}
```

**Capture variables for cross-step data flow:**
```json
{
  "trigger": [{
    "type": "fetch",
    "url": "https://target/search?q=' OR 1=1--",
    "capture": { "status": "sqliStatus", "body": "sqliBody" }
  }],
  "oracle": {
    "type": "expression",
    "left": "{{sqliStatus}}",
    "equals": "500"
  }
}
```
The oracle response includes `left` (resolved value), `leftRaw` (original template), and `capturedVars` (all captured variables).

**Composite oracles (`and`/`or`):**
```json
{
  "oracle": {
    "type": "and",
    "checks": [
      { "type": "expression", "left": "{{sqliStatus}}", "equals": "500" },
      { "type": "expression", "left": "{{sqliBody}}", "contains": "SQLITE_ERROR" }
    ]
  }
}
```

**Cross-identity BOLA proof pattern:**
```json
{
  "setup": [{
    "type": "identity",
    "apply": "admin-user"
  }],
  "trigger": [
    {
      "type": "fetch",
      "url": "https://target/api/profile",
      "capture": { "body": "adminProfile" }
    },
    {
      "type": "identity",
      "apply": "attacker-user"
    },
    {
      "type": "fetch",
      "url": "https://target/api/profile/1",
      "capture": { "body": "attackerView" }
    }
  ],
  "oracle": {
    "type": "expression",
    "left": "{{attackerView}}",
    "contains": "{{adminPrivateField}}"
  }
}
```

**Oracle types:**
| Type | Purpose |
|------|---------|
| `fetch` | Check HTTP status/body of last trigger (use `lastTrigger: true`) |
| `effectCheck` | Evaluate a JS expression in the browser (e.g., `window.__xss_proof === 1`) |
| `expression` | Compare captured variables with `equals`, `contains`, `matches` |
| `and` / `or` | Composite: all/any sub-checks must pass |

### Identity Capture & Management

Trowser's identity system captures full browser auth state (cookies, localStorage tokens, headers) for multi-identity testing.

**Capture current identity:**
```
POST /api/identity/capture {"name":"admin-user","description":"Admin session"}
```

**Apply a captured identity:**
```
POST /api/identity/apply {"name":"admin-user"}
```

**List/get/delete identities:**
```
GET /api/identity/list
GET /api/identity/get?name=admin-user
DELETE /api/identity/delete {"name":"admin-user"}
```

**Identity in verify-workflow:**
Use `{ "type": "identity", "apply": "admin-user" }` as a setup or trigger step to switch auth context mid-workflow.

**SSO handoff:** `POST /api/identity/handoff` for transferring identity state between Trowser instances.

**Inferred mechanism:** When capturing, Trowser detects the auth mechanism: `cookie-session`, `storage-token` (JWT in localStorage), `header-bearer`, etc. This determines how the identity is applied later.

### Evidence Export & Fix-Verification Cycle

The evidence system enables reproducible proof bundles and regression testing after fixes.

**Export evidence bundle:**
```
POST /api/security/evidence/export {"workflowId":"<workflow-id>"}
```
Saves the workflow definition, captured network traffic, and oracle results to a local bundle directory.

**Rerun after fix:**
```
POST /api/security/evidence/rerun {"bundlePath":"<path-from-export>"}
```
Re-executes the proof workflow and compares results. If the vulnerability is fixed, `verified` will be `false` and `verdict` will show the fix was effective.

**Fix-verification workflow:**
1. Create and run a verify-workflow that proves the vulnerability
2. Export the evidence bundle
3. Developer applies the fix
4. Rerun the bundle — if the oracle now fails, the fix works
5. Include both runs in the security report as before/after proof

### VPX Export (Assessment Package)

Export the full security assessment as a machine-readable VPX (Vulnerability Proof eXchange) package:
```
GET /api/vpx/export
```

Returns all attack surfaces, findings, proofs, and verdicts in a structured format suitable for import into other security tools or compliance systems.

### Secrets Harvest Methodology

`POST /api/security/secrets-harvest` scans all captured network responses and JS bundles for credentials, tokens, and sensitive data.

**Best practices:**
- Browse extensively first — the harvest scans everything in the network log
- Pay special attention to CRITICAL findings (email + password combos, full API keys)
- Check JS bundles (especially main.js / app.js) for hardcoded test credentials
- Look for `password`, `secret`, `apiKey`, `token`, `authorization` patterns in API responses
- Correlate with `storage` audit (localStorage/sessionStorage) for client-side secrets

### WAF Bypass Testing

`POST /api/security/waf-bypass` detects WAF presence and tests bypass techniques:
```json
{
  "safetyMode": "active",
  "url": "https://target/search?q=<script>alert(1)</script>"
}
```

Returns which bypass techniques succeed: `double-url-encoding`, `unicode-overlong`, `case-alternation`, `null-byte`, `comment-insertion`, etc. Use successful bypasses to re-test XSS and SQLi payloads that were initially blocked.

### GraphQL Security Analysis

`POST /api/security/graphql-analyze` probes GraphQL endpoints:
```json
{
  "safetyMode": "active",
  "url": "https://target/graphql"
}
```

Tests: introspection exposure, query depth limits, batch query abuse, field suggestion leaks. Works gracefully even on non-GraphQL endpoints (reports "introspection disabled" rather than crashing).

### WebSocket & CSWSH Testing

- **WebSocket audit:** `POST /api/security/websocket-audit` — analyzes active WebSocket connections for authentication, message patterns, and data exposure
- **CSWSH test:** `POST /api/security/cswsh-test` — tests Cross-Site WebSocket Hijacking by attempting WebSocket connections without proper origin validation

### Build Regression Testing
After each new build, re-run the exact requests that previously caused 500s via `/api/fetch`. Compare status codes to confirm fixes and detect regressions.

### Shadow Mode as Passive Net
Enable shadow mode at session start. It catches 500s, security header issues, credential patterns, SQL error signatures, and CAPTCHA answer leaks automatically while you focus on targeted testing. Check findings periodically with `GET /api/security/shadow`.

---

## Report Compilation
After testing, compile findings from:
- Automated scan results (`security`, `security-headers`, `xss`, `cookies`, `cors`, `source-maps`, `storage`, `mixed-content`, `firewall-test`)
- Attack surface inventory
- **Attack chain analysis** (`chain-analyze` confirmed and partial chains)
- **Chain-prove results** (proven chains with per-step evidence)
- **Verify-workflow proofs** (custom proof workflows with oracle verdicts)
- **Evidence bundles** (exported proof packages for reproducibility)
- SAML decode output (if applicable)
- Manual findings from `fetch`, `execute-js`, `intercept`, and dual-session testing
- Shadow mode passive findings
- Secrets harvest results
- Journal entries
- **VPX export** for machine-readable assessment exchange

Rate each finding by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO) and include reproduction steps, evidence, and remediation recommendations. For findings with verify-workflow proofs, include the workflow definition and oracle evidence as definitive proof.
