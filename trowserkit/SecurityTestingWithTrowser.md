# Security Testing with Trowser — Methodology Guide

A concise guide for AI-driven and manual security testing using the Trowser REST API. You will also have the Trowser API reference (`trowser-api-reference.md`) and endpoint index (`trowser-api-index.md`); this guide focuses on **methodology, patterns, and gotchas** rather than repeating API docs.

Every call in this guide is a REST request on the local API (default `http://localhost:6923`, `Authorization: Bearer <api-key>` except `GET /api/ping`). MCP tool names map to those paths (e.g. `browser_security` → `POST /api/security`, `browser_security_js_libraries` → `POST /api/security/js-libraries`, `browser_security_headers` → `POST /api/security/headers`). If the MCP server is down, use the REST paths.

---

## Trowser assists — it does not replace you

Trowser’s REST API, MCP tools, and security playbooks are **helpers**, not a turnkey vulnerability scanner or a substitute for a skilled tester. Plan on doing **substantial work outside** what any single endpoint or orchestrated run can do.

**What automation tends to miss or under-test**

- Application-specific **business logic** (checkout rules, entitlements, race windows, “impossible” state transitions)
- **Novel** bugs that do not match bundled probe templates or heuristics
- Flows you never **browsed** or captured in the network log (playbooks default to `crawl: false` for a reason)
- **Federation** depth (SAML/OIDC edge cases), custom protocols, and non-REST surfaces
- Judgment calls: false positives, severity, exploitability, and whether a lead is worth pursuing

**What you should still expect to do**

- **Explore the app** like a user (and like an attacker): multi-step flows, alternate roles, error paths, admin vs. user surfaces
- **Prove** findings manually — replay with precise parameters, peer sessions, intercept/fulfill, or external tools (Burp, curl) when that is clearer than a generic scan
- **Follow leads** from partial signals (`nextActions`, DOM/client-source bundles, Swagger/OpenAPI, server or mobile code if you have it)
- **Invent tests** the product team did not document: mass assignment, IDOR on opaque IDs, host-header and cache chains, LLM prompt paths, etc.

A clean playbook report does **not** mean the target is secure. Treat Trowser output as **prioritized hypotheses and coverage hints**; your job is to validate, deepen, and find what automation did not.

---

## Scanner provenance

Trowser **owns** its security probe implementations. Detection design is aligned with public methodologies — primarily **OWASP WSTG**, **PortSwigger** research/Academy techniques, **OWASP API Security**, relevant **RFCs**, and vendor advisories — plus Trowser-specific traffic/session/scaffold behaviour.

---

## Playbooks first, this guide second

Trowser ships **security playbooks** — orchestrated scanners aligned with the **Trowser Twelve** taxonomy (OWASP Top Ten–inspired IDs, extended for SSRF, availability, and LLM risks). Each playbook runs a curated chain of primitives in the right order, applies a uniform `safetyMode`, correlates findings, and returns `nextActions` plus suggested proofs.

### Trowser Twelve — names, IDs, and twelve playbooks

The Quicktests group **Trowser Twelve** runs **twelve category playbooks** — one orchestrated pipeline per major risk area (`A01`–`A07`, `A09`, `A11`–`A14`). IDs use **`Axx` labels up to A14**; that is not “fourteen playbooks.” Two IDs are **intentionally unused** so extended categories stay stable:

| ID | Dedicated playbook? | Where coverage lives |
|----|---------------------|-------------------|
| **A08** | No | **Software and data integrity** (SRI, CI/CD/manifest exposure, deserialization, upload integrity) — primarily **`a03-supplychain`** and active integrity probes in **`auto-scan`** / A03 steps |
| **A10** | No | Reserved (OWASP 2021 used A10 for SSRF). **SSRF** is **`a11-ssrf` (A11)** so A11–A14 name extensions without renumbering A09 |

Injection also has **`a05a` / `a05b` / `a05c`** slices; **`full`** and **`quick`** span multiple categories. VPX `owasp` fields use the same ID set (`A01`–`A07`, `A09`, `A11`–`A14`).

### Recommended workflow (fast, focused)

**Browse manually, then scan with `crawl: false`.** Playbooks default to `crawl: false` so they analyze traffic you already captured instead of spending budget on an automatic crawl.

1. Complete **Phase 0 — Setup** (below).
2. **Browse key flows** (login, search, CRUD, checkout) — 5–10 pages or the flows you care about — to populate the network log.
3. Run a playbook with **`"crawl": false`** (the default). For injection and other probe-heavy playbooks, set **`scope.targetUrl`** to one captured endpoint, or use **`depth: "deep"`** only when you explicitly want broader endpoint coverage.
4. Triage the report: severities, `nextActions`, partial attack chains.
5. Use the **sections below** (and Track B checklist items) to prove, deepen, or manually test what the playbooks surfaced.

Set **`"crawl": true`** only when you have not browsed yet and want the playbook to auto-discover links/forms on `scope.host` before scanning. Crawl and probe selection default to **`scope.excludeLogout: true`** (skip logout/sign-out/SLO URLs) so an auto-crawl does not end the session; add **`scope.excludePaths`** / **`excludeUrlPatterns`** for other pages you must not touch. Intentional logout testing still uses **`a07-authn`** / `logout-invalidation-probe` separately, or the semi-manual **TotalLogoutTest** quicktest (capture session, you log out, replay client auth).

Preview a playbook's step plan without executing: `POST /api/orchestrate/dry-run/{id}`. List available playbooks: `GET /api/orchestrate/playbooks`. GUI equivalent: Script Console → Quicktests → Security → **Trowser Twelve** (menu names, prerequisites, and REST parity: **[QuicktestsForSecurityTesting.md](QuicktestsForSecurityTesting.md)**).

**When to skip playbooks and use this guide directly (depth / full control):**

- SAML / federation deep dives (Phase 4 — not yet a dedicated playbook)
- Custom fuzz templates, intercept/fulfill MITM, dual-session attacks
- Application-specific business logic, creative manual exploration
- Following up on a single finding with precise parameters (trace-input selectors, authz peer diffs, SAML replay variants)
- **Client-source-led investigation** — you want DOM XSS, postMessage, client PP, or open-redirect leads from the bundles that actually run (see below), before or instead of a broad scanner pass
- You already ran playbooks and need the **how-to** for proof, verification, or false-positive triage

Playbooks **wrap** the same REST primitives documented here — they do not replace the patterns and gotchas in the body of this file.

### Playbook → drill-down map

| Playbook ID | Endpoint | Use this guide for follow-up |
|-------------|----------|------------------------------|
| `full` | `POST /api/orchestrate/full` | Phase 4b–4c (chains, proof), Phase 7 (reporting) |
| `quick` | `POST /api/orchestrate/quick` | Default LLM sweep (~60–120s); then `a07-authn` if session testing needed |
| `a01-access` | `POST /api/orchestrate/a01-access` | Authorization Testing (`authz/*`), BAC APIs, IDOR Testing |
| `a02-misconfig` | `POST /api/orchestrate/a02-misconfig` | Phase 2 individual scans, gotchas (discover on SPAs); passive rollup also **`POST /api/security`** (Quicktest **1 Security Scan**) |
| `a03-supplychain` | `POST /api/orchestrate/a03-supplychain` | Secrets Harvest Methodology |
| `a04-crypto` | `POST /api/orchestrate/a04-crypto` | Secrets Harvest Methodology, session/cookie checks, IndexedDB dump |
| `a05-injection` | `POST /api/orchestrate/a05-injection` | XSS Testing, **Client-source-led investigation**, Fuzzing, Injection Testing, DOM flow graph (full; ~1800s) |
| `a05a-injection-core` | `POST /api/orchestrate/a05a-injection-core` | Short agent slice: cmd-canary + XSS + SQLi + observe DOM flows (~300s) |
| `a05b-injection-templates` | `POST /api/orchestrate/a05b-injection-templates` | SSTI / polyglot / CSTI / NoSQL / LDAP / path |
| `a05c-injection-advanced` | `POST /api/orchestrate/a05c-injection-advanced` | Login-sweep, deser, upload, parser, prototype pollution |
| `a06-design` | `POST /api/orchestrate/a06-design` | Business logic, race conditions (Phase 3 & 6) |
| `a07-authn` | `POST /api/orchestrate/a07-authn` | Brute-Force / Account Lockout, session testing |
| `a09-opsec` | `POST /api/orchestrate/a09-opsec` | Forced-error interpretation, log-leak triage |
| `a11-ssrf` | `POST /api/orchestrate/a11-ssrf` | SSRF follow-up with custom payloads |
| `a12-availability` | `POST /api/orchestrate/a12-availability` | Rate limits, body-size, ReDoS, GraphQL cost; passive **costly-operations** step (`POST /api/security/costly-operations`) |
| `a13-llm` | `POST /api/orchestrate/a13-llm` | LLM application-layer Top 10: corpus + RAG poison + unbounded consumption + output→sink |
| `a14-other` | `POST /api/orchestrate/a14-other` | Smuggling, host-header, cache-identify → map → pollution → poison, open redirect, XS-Leaks (Phase 6) |
| *(none)* | — | **Phase 4 — SAML / Federation** (manual-first) |

### OWASP LLM Top 10 coverage (A13 / `llm-redteam-scan`)

| Category | Status | How |
|----------|--------|-----|
| LLM01 Prompt Injection | Covered | YAML corpus + indirect/RAG upload |
| LLM02 Sensitive Disclosure | Covered | YAML corpus |
| LLM03 Supply Chain | Covered (light) | Model/plugin fingerprint probes |
| LLM04 Data/Model Poisoning | Adjacent | `includeRagPoison` (document/memory persistence) — not training-set poisoning |
| LLM05 Improper Output Handling | Covered | YAML + DOM render check + A13 sink-trace |
| LLM06 Excessive Agency | Covered | YAML + WebMCP tool invocation abuse |
| LLM07 System Prompt Leakage | Covered | YAML corpus |
| LLM08 Vector/Embedding | Adjacent | Peer cross-tenant check via `peerBaseUrl` on rag-poison |
| LLM09 Misinformation | Covered | Canary CVE/DOI/URL fabrication probes |
| LLM10 Unbounded Consumption | Adjacent | `includeUnboundedConsumption` (flood / oversized / max-output / tool-loop) |

Scan responses include `coverage.covered` / `coverage.notCoveredInCorpus`. Claim: **application-layer OWASP LLM Top 10**; training-time risks remain out of scope.

Common playbook request envelope:

**Canonical budget workflow:** call dry-run first, then copy `recommendedBudget` into the real run. Do **not** treat `maxSeconds: 120` as a normal envelope for probe playbooks — that default often marks core steps `skippedByBudget` (`coverageIncomplete: true`).

```json
// 1) POST /api/orchestrate/dry-run/a05a-injection-core
// 2) Use data.recommendedBudget from the response:
{
  "scope": {
    "host": "example.com",
    "targetUrl": "https://example.com/api/search?q=test"
  },
  "safetyMode": "active",
  "depth": "llm",
  "crawl": false,
  "budget": { "maxSeconds": 300, "maxRequests": 800 },
  "emitSuggestedProofs": true
}
```

If dry-run returns `coverageIncomplete: true`, raise the budget (or use `depth: "llm"` on a05a) before executing. Use `"safetyMode": "active"` when injection, fuzz, smuggling, or other live probes are required. See the API reference orchestration section for full options.

---

## Quick-Start Checklist

Two tracks share **Phase 0**. Most sessions should use **Track A** for coverage, then **Track B** (or the detailed sections below) for follow-up.

### Phase 0 — Setup (both tracks)
- [ ] Verify connection: `GET /api/ping`
- [ ] Set headers: `$h = @{Authorization="Bearer <key>"; "Content-Type"="application/json"}`
- [ ] Navigate to target
- [ ] Fill fields with **`POST /api/type`** (there is **no `/api/fill`** — `/api/type` clears first; use `"append": true` to append)
- [ ] Enable Shadow: Settings → Experimental, or `POST /api/security/shadow {"enabled":true,"suggestions":true}`
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
- [ ] Phase 7 — Verification & Reporting

### Track B — Manual primitives & follow-up

Use when playbooks are insufficient, you need full control, or you are **drilling into** playbook findings. Each phase builds on the previous one.

### Phase 1 — Reconnaissance

*Most items covered by playbook crawl + attack-surface steps. Run manually for extra control or when not using playbooks.*

- [ ] Browse 5–10 key pages to populate the network log
- [ ] **API / SPA: grab the spec first.** `GET` the OpenAPI document (`/swagger-json`, `/swagger/v1/swagger.json`, `/openapi.json`, `/api-docs`) before broad scanning. On NestJS and similar SPAs this is the highest-value Phase 1 move — it names routes the UI never links. Then **Swaggering** (below) replays those operations with the logged-in session.
- [ ] Map attack surface: `POST /api/security/attack-surface {"includeParameters":true}` (agents: add `"includeApiEnrichment":false` for a fast network-log map; see Phase 1)
- [ ] Fetch and analyze JS for dangerous sinks — quick pass: `POST /api/security/secrets-harvest` / `POST /api/security/js-audit` (`safetyMode: "active"`); depth: **Client-source-led investigation** (below)
- [ ] Cookie HttpOnly: `POST /api/security/cookies` (jar + Set-Cookie reconciliation) and `GET /api/cookies`; cross-check `document.cookie` via `execute-js` — **an empty string is not proof** (no readable cookie on this path, HttpOnly, or domain/path mismatch)
- [ ] Check response headers: `POST /api/security/headers` (document URL; CSP, HSTS, X-Frame-Options, TRACE, etc.) or `/api/fetch` for a specific URL
- [ ] Identify tech stack: `POST /api/security/tech-stack` (or `browser_security_tech_stack`) — detects servers, frameworks, WAFs, CDNs, JS libraries from headers, cookies, DOM

### Phase 2 — Automated Scans

*Largely covered by `a02-misconfig`, `a03-supplychain`, `a04-crypto`, and `full`. Run individual scans for targeted re-checks.*

- [ ] Run `POST /api/audit-all` for a broad **page-health** baseline (a11y, perf, SEO, OWASP rollup modules — heavier than security-only)
- [ ] Or run **`POST /api/security`** — passive **Security Scan** overview (same modules as Quicktests → **1 Security Scan**: tech stack, Retire.js CVEs, headers, CORS, XSS, mixed content, cookies, source maps, storage, HTTP methods, discover). Retire.js only: **`POST /api/security/js-libraries`**
- [ ] Or run individual scans: `/api/security/headers`, `/api/security/cookies`, `/api/security/cors`, **`/api/security/xss`** (passive DOM sink/source audit — not active probing), **`/api/security/dom-xss-audit`** (first-choice **active DOM XSS** on the **current page**: passive patterns + dom-flow probe + trace-input on query/hash — one call), **`/api/security/xss-scan`** (alias **`/api/security/xss-dom-audit`** — **not** the same as `dom-xss-audit`; reflected HTTP + optional stored + lighter DOM navigation probes from the network log), **`/api/security/trace-input`** (single-parameter precision / form fields / one-off repro after a finding), `/api/security/mixed-content`, `/api/security/source-maps`, `/api/security/storage`, `/api/security/firewall-test`, `/api/third-party`, `/api/security/methods`, `/api/security/discover`, `/api/security/path-traversal`, `/api/security/csrf`
- [ ] Run `POST /api/security/auto-scan` — detects SQLi, IDOR (path params), method enumeration, CSRF in one call
- [ ] Run `POST /api/security/secrets-harvest` — finds credentials, tokens, API keys in network responses and JS bundles
- [ ] Run `POST /api/security/nuclei-scan` — embedded exposure templates; add **`templatesDir`** for app-specific YAML (see Nuclei below)
- [ ] Check identity state: `GET /api/session/identity` — shows current session info and cookies
- [ ] If SAML: `POST /api/security/saml-decode {"source":"network","findAll":true}`
- [ ] If JWT: `POST /api/security/jwt-analyze {"safetyMode":"active"}`

### Phase 3 — Active Testing

*Core coverage in `a01-access`, `a05-injection`, `a06-design`, `a07-authn`. Use this phase for precision follow-up and business-logic testing.*

- [ ] **Authentication:** brute-force, credential stuffing, account lockout, timing oracle
- [ ] **Authorization (manual):** IDOR via `fetch/batch`, role escalation, cross-tenant access
- [ ] **Authorization (authz APIs):** `authz/diff`, `authz/boundary`, `authz/probe`, `authz/fuzz` (see below)
- [ ] **BAC — ID Harvesting:** `harvest-ids` → POST `suggestedBoundaryTests[]` to `authz/boundary` (browse object pages first)
- [ ] **BAC — JWT Sweep:** `jwt-acceptance-sweep` for alg:none + missing-auth on JWT sites
- [ ] **BAC — Auth Bypass Pivot:** `auth-bypass-pivot` with captured bearer token
- [ ] **BAC — REST Scaffold:** `rest-scaffold` for unauthenticated REST API exposure
- [ ] **BAC — Path Filter Bypass:** `path-filter-bypass` for NUL-byte/encoding bypasses (verify findings manually — see gotchas)
- [ ] **Injection:** SQLi, XSS (stored + reflected + DOM), SSTI, LDAP, CRLF, path traversal
- [ ] **CSRF:** Test all state-changing operations with missing/invalid/cross-session tokens
- [ ] **Business logic:** price tampering, negative quantities, mass assignment, pagination abuse
- [ ] *(Session and auth depth — Phase 5 checklist and section below)*

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
- [ ] Capture a repro from the checkpoint trail: `POST /api/repro/capture {"checkpointId":"<id>"}`
- [ ] Verify / rerun proofs after fixes: `POST /api/repro/verify {"bundlePath":"<path>","expect":"not-reproducible","safetyMode":"active"}`
- [ ] Export full assessment: **Settings → Experimental… → VPX Export…** or `GET /api/vpx/export`

### Phase 5 — Session & Authentication Testing

*Core coverage in `a07-authn` and Phase 3 active items. Use this phase for cookie/session precision and enumeration oracles.*

- [ ] Cookie read/tamper/delete: `/api/cookies`, `/api/cookies/set`, `/api/cookies/delete`; cross-check `document.cookie`
- [ ] Session fixation (fabricated session IDs)
- [ ] Timing oracle / user enumeration via `/api/fetch` or `/api/fetch/batch` (`durationMs`)
- [ ] Brute-force, credential stuffing, account lockout (when not fully covered by playbook)
- [ ] Concurrent login / session collision behavior

### Phase 6 — Advanced Attacks

*Partial coverage in `a14-other`, `a06-design`, `a12-availability`. Manual items: intercept, interrupter, dual-session, custom fuzz.*

- [ ] MITM simulation via `intercept/fulfill` (response tampering)
- [ ] Fault injection via `interrupter`
- [ ] Race conditions via `fetch/batch {concurrent:true}` or `load-test`
- [ ] **Race Lab** (multi-session, TOCTOU): `POST /api/peer/spawn` or `POST /api/peer/register` (second Trowser on another port) → **More options → Race Lab…** or `POST /api/race-lab/run` with `requests[]` (`session`: **`all-peers`** (default) \| `driver` \| peer name; `role`: **`observe`** (default) \| `mutate` \| `check`; optional **`responsePattern`** regex on any row). Use **`mutate`** only for single-use/state-changing endpoints. Quick traffic discovery: `POST /api/security/race-condition-scan`. REST examples: [Race Lab](trowser-api-reference.md#race-lab-multi-session-race--toctou).
- [ ] Dual-session attacks (if two Trowser instances available)
- [ ] Content-Type confusion, HTTP method override
- [ ] HTTP request smuggling: `POST /api/security/smuggling {"safetyMode":"active"}` — **act only on `verdict: confirmed`** (differential 404)
- [ ] Manual TE/CL or duplicate-header confirmation: Use `POST /api/fetch-raw` (HTTP/1.x bytes; put a second request in `body` to pipeline). Session header overrides do not apply.
- [ ] Host header injection: `POST /api/security/host-header {"safetyMode":"active"}` (or `discoverFromNetwork:true` after browsing reset flows)
- [ ] Mass assignment: `POST /api/security/mass-assignment-scan {"safetyMode":"active"}` — test if extra fields in POST/PUT bodies get accepted (register/patch variants: `mass-assignment-register`, `mass-assignment-patch`)
- [ ] WAF bypass: `POST /api/security/waf-bypass {"safetyMode":"active"}` — detect and bypass WAF protections
- [ ] GraphQL analysis: `POST /api/security/graphql-analyze {"safetyMode":"active"}` — introspection, depth limits, batch abuse
- [ ] WebSocket audit: `POST /api/security/websocket-audit` — connection auth and message analysis
- [ ] SSE audit: `POST /api/security/sse-audit` — EventSource streams (passive + capped active subscribe checks); list streams with `GET /api/sse/connections`
- [ ] CSWSH test: `POST /api/security/cswsh-test` — Cross-Site WebSocket Hijacking
- [ ] Open redirect, clickjacking

### Phase 7 — Verification & Reporting
- [ ] Confirm all XSS execution via `execute-js`
- [ ] Confirm **JS-readable** session cookie theft via `document.cookie` only when `/api/cookies` shows the session cookie is not HttpOnly; otherwise prove impact another way (session replay, XSS exfil, etc.)
- [ ] Verify MITM chains via `intercept/fulfill`
- [ ] Check shadow mode for passively detected issues
- [ ] Check OOB callbacks
- [ ] Run `chain-prove` on all provable chains
- [ ] Build verify-workflow proofs for critical/high findings
- [ ] Capture or export repros: `POST /api/repro/capture` (checkpoint trail) or `verify-workflow` with `exportEvidence: true`
- [ ] Export VPX assessment package: **Settings → Experimental… → VPX Export…** or `GET /api/vpx/export`
- [ ] Export journal and compile severity-rated report
- [ ] On user request, create .trw files for reproduction (`POST /api/repro/capture` or `POST /api/test-scenario`)


---

## Phase 1 — Reconnaissance

### Attack Surface Mapping
Browse the app first (navigate, click, fill forms) to populate the network log, then run:
```
POST /api/security/attack-surface {"includeParameters":true,"includeAuth":true,"includeResponsePatterns":true}
```
Filter by host with `"host":"target.example.com"`. Use the returned request body samples as templates for fuzzing and IDOR testing.

**Agent-friendly fast pass** — default enrichment probes OpenAPI paths, dev artifacts, and JS bundles server-side and holds the API gate (often 30s–2min). For playbook prep after browsing, prefer:
```
POST /api/security/attack-surface {"host":"target.example.com","includeParameters":true,"includeApiEnrichment":false,"includeApiInventory":false}
```
Turn enrichment back on when you want passive OpenAPI/WP-json discovery from traffic plus lightweight GET probes. `POST /api/abort` cancels enrichment mid-run (same `OperationCancellation` as auto-scan).

### Swaggering (OpenAPI + the logged-in session)

On an API-backed SPA, fetching the spec is reconnaissance, not a mid-list extra. `GET /swagger-json` (or `/openapi.json`, `/swagger/v1/swagger.json`, `/api-docs`) before scanners. Swaggering then loads that document and calls the documented operations with the browser cookie jar (and CSRF or API headers captured from matching traffic). It is a contract smoke test, not a full pentest of the API.

**Before you call it**

1. Log in in the WebView so session cookies exist.
2. Prefer an explicit spec URL. Well-known probes include `/openapi.json`, `/swagger/v1/swagger.json`, `/api/v3/openapi.json`, and `/v2/swagger.json`. If the spec lives somewhere else, pass `specUrls`. Opening Swagger UI also works: the document is taken from the network log.
3. Agents should set a budget. Default `depth` is `thorough` (~20 minutes) and holds the API gate. Use `standard` or `quick` plus `maxStepSeconds` for a first pass.

```
POST /api/security/swaggering
{
  "safetyMode": "active",
  "depth": "standard",
  "maxStepSeconds": 180,
  "specUrls": ["https://app.example/api/v3/openapi.json"]
}
```

`passive` only discovers the spec and reports spec-cost hints. `safe` sends GET/HEAD/OPTIONS. `active` also sends POST/PUT/PATCH. DELETE stays out unless `includeDeleteMethods` is true.

**What to read**

| Field | How to use it |
|-------|----------------|
| `message` | Counts swaggering findings, spec-cost hints, and auto-scan findings. A green message means this run did not flag an issue. It does not mean the API is safe. |
| `operations[]` | One row per catalog operation: `outcome` (`probed`, `skipped`, `not-probed`, `not-reached`), smoke `status`, and the URL that was called. This is the coverage map. |
| `coverage` | Totals for probed, skipped, not probed (passive), and not reached, plus 2xx / 4xx / 5xx on the smoke request. |
| `findings[]` | `swaggering-server-error`, `swaggering-verbose-error`, `swaggering-slow`, `swaggering-auth-anomaly`, `swaggering-shadow-exposed`, `swaggering-injection-hint`, `swaggering-sensitive-data`. `evidence` is a short response excerpt. Secret values are not copied; sensitive-data findings list field names only. |
| `costlyFindings[]` | Passive limit/array hints from the spec that was loaded. |
| `shadowPaths[]` | Traffic paths that are not in the spec. The spec file and Swagger UI assets are not listed. |
| `autoScan` | Injection and access checks against the catalog and observed traffic. Generic paths such as `/rest/products/search` are not added. |
| `warnings` | 401/403 on a spec URL means log in and retry. Ordinary 404s from guessed spec paths are omitted. |
| `partial` / `budgetExhausted` | The run stopped early. `operations[].outcome` of `not-reached` is what was skipped. |

`requestsSent` counts Swaggering's own HTTP calls. Those calls use the cookie jar from the server, so they do not appear in `GET /api/network`. To re-check a finding, call `POST /api/fetch` (same origin) or repeat the URL from `findings[].url`.

**Depth**

| `depth` | What you get |
|---------|----------------|
| `quick` | Smoke only. No auth-delta, forced-error, missing-field, cost edge, injection micro, shadow GET, or auto-scan. |
| `standard` | Those lanes, plus auto-scan. About 8 minutes unless `maxStepSeconds` is set. |
| `thorough` | Larger caps. About 20 minutes on a large spec. |

A 500 that repeats on the `edge` variant of the same operation is reported once. Compare `operations[].status` with `findings[].evidence` before treating a 500 as a bug in the generated body — many demo APIs return 500 for a valid call too.

**Follow-up when something looks real**

- `swaggering-sensitive-data` on a 2xx: fetch that URL and confirm the field is a live secret, then try it without the session cookie.
- `swaggering-auth-anomaly`: the spec declares security and a write succeeded with no cookies. Repeat with an explicit unauthenticated `POST /api/fetch`.
- `swaggering-server-error` with a stack trace in `evidence`: treat as `swaggering-verbose-error` if that category is also present; otherwise quote the excerpt.
- Spec-cost hints (`costly-spec-unbounded` and similar): they are leads. Confirm with one bounded request, not a load test, unless that is in scope.

### Technology Stack Discovery
Run in parallel for speed: `/api/security` (overview) or `/api/security/js-libraries` (Retire.js only), `/api/security/headers`, `/api/third-party`. Fetch and search JS files for `eval(`, `innerHTML`, `document.write(`, `postMessage(`.

### In-Browser Analysis
Use `/api/execute-js` to inspect the page context:
- `document.cookie` — what JavaScript may read on **this document**; compare with `GET /api/cookies` and `POST /api/security/cookies` (Set-Cookie attributes). Empty does not by itself prove HttpOnly on the session cookie.
- `document.querySelectorAll('script:not([src])')` — count inline scripts
- `window.__NEXT_DATA__` or `window.__NUXT__` — framework-specific data leaks

For static review of external bundles, prefer `POST /api/fetch` with `"serverSide": true`, `POST /api/security/js-audit`, and `POST /api/security/source-maps` — not in-page `fetch()` inside execute-js (see gotchas).

### Full-stack source (optional, out of band)

Trowser tests the **running app** in WebView2. When you have access to the product repo, reading **server** and **mobile** code is one of the highest-yield ways to get leads: authorization checks, deserialization, webhooks, feature flags, and debug endpoints rarely show up in a passive crawl alone. This guide does not walk through backend SAST — treat that as parallel work that feeds hypotheses you later prove with `fetch`, playbooks, and peer sessions. The section below focuses on what you can do **in the browser** with client-side JavaScript and maps.

### Client-source-led investigation

An **alternative starting lane** for client-side risk — not a mandatory preflight before playbooks, and not a substitute for active probes. Use it when DOM XSS, postMessage, client-side open redirect, prototype pollution, or “why does this param exist?” questions are cheaper to answer from code than from guessing scanner params.

**Pin context first.** Open or switch to the **agent tab** you intend to test (`GET /api/tabs`; pin with `POST /api/tabs/new` + `"owner": "agent"` or let the first agent navigate/click create one). Navigate to one real page (including lazy routes — checkout, admin, hash routes). Inventory what actually runs: `GET /api/network` (script/stylesheet entries), inline blocks via `execute-js`, and `POST /api/security/client-surface` for runtime sources/sinks/listeners. After SPA navigations, re-run inventory — chunk URLs change.

**Acquire and validate source.** For each interesting script URL:

1. Confirm final URL, status, and `Content-Type` (`application/javascript` or `text/javascript`; reject HTML login walls and SPA shells).
2. Fetch with `POST /api/fetch` `"serverSide": true` (or `POST /api/security/js-audit` / `POST /api/security/secrets-harvest` for heuristic secret passes). Optionally follow `POST /api/security/source-maps` to original TypeScript when `.map` is exposed.
3. Record a content hash or byte length so you can reuse reviewed files on the next page without re-downloading everything.

**Separate framework from application code.** Minified vendor bundles (React, Angular, lodash) are noise unless you are testing supply chain/version CVEs. Focus on app chunks (`main`, `pages`, route-specific lazy files). Identify **one concrete trust boundary** per investigation: URL query/hash/path, form field, `postMessage` payload, server-rendered HTML fragment, API JSON field used in a selector, navigation target, analytics/telemetry blob, or storage key.

**Follow source to sink or request.** In the bundle, search from the boundary (router param parsers, `location.search`, `JSON.parse`, `innerHTML`, `eval`, `Function`, template compilers, `fetch`/`axios` builders). State **who can control the input** (any visitor, authenticated user, another origin via postMessage) and which **server or browser controls** still apply (CSP, Trusted Types, sanitizer, prefix checks on redirect URLs, cookie flags).

**Establish a baseline in the same context.** With `safetyMode: "active"`, use minimal synthetic values and **`POST /api/security/trace-input`** or **`dom-xss-audit`** on the **same tab and origin** you used for source review. Inspect both the **network request** the client emits and **runtime DOM/CSP** behavior (`browser_console`, `browser_network`, firewall-test when CSP is in play). A scanner “HIGH” without a matching source→sink story stays a lead until trace-input confirms.

**Mocks and isolation.** `POST /api/mock` / intercept only to isolate a renderer path or stub an API object — label all derived evidence **synthetic**. Before claiming exploitability, reproduce through a **legitimate upstream path** (real form submit, real API response shape, real postMessage from an allowed origin).

**Record outcomes explicitly** — pick one label per thread:

| Label | Meaning |
|-------|---------|
| Verified vulnerability / weakness | Source→sink→impact confirmed in browser with realistic control |
| Conditional lead | Code path exists; missing attacker prerequisite (auth, second step, specific header) |
| Blocked vector | Sink reachable in source but CSP/sanitizer/prefix check stops execution in trace-input |
| Negative check | Reviewed boundary; no dangerous sink in app code for this page |
| Untested prerequisite | Needs map chunk, login role, or feature flag you have not loaded yet |

Do not upgrade an HTTP status code or a passive scanner tier to “proof” without trace-input or verify-workflow confirmation.

**Clean up and iterate.** Clear mocks/intercept rules, `GET /api/state` on the tab you used, then navigate to the next route. Reuse cached script hashes from earlier steps instead of restarting a whole-app `POST /api/security/js-audit` on every page.

**Trowser primitives (quick map)**

| Step | APIs |
|------|------|
| Runtime map | `POST /api/security/client-surface`, `POST /api/security/dom-flows`, passive `POST /api/security/xss` |
| Static bundles | `POST /api/security/js-audit`, `POST /api/security/secrets-harvest`, `POST /api/security/source-maps`, attack-surface with `includeJsBundleHints` |
| Prove client bugs | `POST /api/security/trace-input`, `POST /api/security/dom-xss-audit` (`depth: "deep"` when client-surface + all query keys matter), `POST /api/security/verify` |
| postMessage / workers | client-surface → dedicated postMessage audit / `service-worker-audit` per `nextActions` |

Pair with **XSS Testing** (Phase 3) once you know the param name and sink from source — scanners find candidates; source tells you **which** `trace-input` call is worth making.

---

## Phase 2 — Automated Scans

### All-in-One

| Endpoint | Role |
|----------|------|
| `POST /api/security` | **Security Scan** overview on the current page (Quicktest **1 Security Scan** parity): tech stack, Retire.js, headers, CORS, XSS, mixed content, cookies, source maps, storage, methods, discover. Optional body: `includeDiscover`, `includeMethods`, discover wordlist options. |
| `POST /api/audit-all` | Full **page health** (accessibility, performance, SEO, link check, GUI consistency, plus security slices: CVE via `js-libraries`, XSS, mixed content, source maps, headers, cookies, storage, supply-chain hints, secrets harvest, misconfiguration, and more). Use when quality + security rollup is the goal. |

### Individual Scans Worth Running
| Endpoint | What It Catches |
|----------|----------------|
| `/api/security/js-libraries` | Retire.js known CVEs in loaded JS (narrower than the full overview) |
| `/api/security/tech-stack` | Servers, frameworks, WAF, CDN, cache layer from headers/DOM |
| `/api/security/mixed-content` | HTTP subresources on HTTPS pages |
| `/api/security/methods` | Dangerous HTTP methods on the document URL (TRACE, etc.) |
| `/api/security/xss` | Passive DOM XSS patterns (sinks and sources in the current page) |
| **`/api/security/dom-xss-audit`** | **Active DOM XSS orchestrator** on the current URL: client-surface (optional), passive XSS, dom-flow probe, trace-input on all query keys + hash. Prefer this over `xss-scan` when you care about hash/search/DOM-sourced XSS on the page you are on. |
| `/api/security/xss-scan` or **`/api/security/xss-dom-audit`** (alias of **xss-scan only**) | Reflected (and optional stored) **HTTP** XSS from logged endpoints; includes DOM navigation probes but **not** the full query/hash trace-input sweep. A clean result does **not** rule out DOM XSS — run **`dom-xss-audit`** or **`trace-input`**. |
| `/api/security/trace-input` | One source at a time (form, `url-query`, `url-hash`, …) with full causality and bypass ladders — best for confirming a specific param or reproducing one finding |
| `/api/security/cookies` | Secure, HttpOnly (jar + Set-Cookie reconciliation), SameSite, domain scoping — JS-set cookies may still need `document.cookie` sanity checks |
| `/api/security/cors` | Reflected origins, wildcard misconfig |
| `/api/security/firewall-test` | CSP enforcement probes (default in-page set plus opt-in `probes`), SRI, iframe sandbox, Permissions-Policy |
| `/api/security/csrf` | Missing CSRF tokens on state-changing endpoints (**browse and submit forms first!**) |
| `/api/security/discover` | Endpoint brute-force. HTML shell / soft-404 duplicates are excluded by default (`spaMode`) |
| `/api/security/path-traversal` | Query-parameter traversal only (path-based requires manual testing) |
| `/api/security/source-maps` | Exposed source maps = full source code disclosure |
| `/api/security/storage` | Sensitive data in localStorage/sessionStorage |
| `/api/security/nuclei-scan` | Embedded + **custom** Nuclei HTTP templates; multi-URL exposure sweep |
| `/api/third-party` | Third-party inventory via eTLD+1 (`hostname` + `etldPlus1`); SRI coverage |
| `/api/security/headers` | Headers + **csp-evaluator** when a CSP is present |

### High-Value Security APIs

These newer APIs provide the deepest security insights and should be run after populating the network log.

**`POST /api/security/auto-scan`** — Composite scanner that detects SQLi, IDOR (path parameters), HTTP method enumeration, CSRF, SSTI, open redirects, and mass assignment from the network log. Returns severity-rated findings. Best run after browsing 5–10 pages. Use **`payloadProfile`: `"big"`** when SecLists/PayloadsAllTheThings corpora are installed (`corpora/` beside the exe or `%TROWSER_CORPORA%`); response echoes `payloadProfile` + `corporaAvailable`.

**`POST /api/security/secrets-harvest`** — Analyzes captured network responses, JS bundles, storage, and request headers for credentials, tokens, and API keys. Volume depends on the target; filter by severity/category (comment hygiene is info-only; CRITICAL is reserved for email+password combos and similar high-confidence hits).

**`POST /api/security/nuclei-scan`** — Native runner over a **small embedded HTTP template subset** plus **your own YAML**. Best for exposure/misconfig (`.env`, `.git`, swagger path lists, app-specific secret paths). Supports **`payloads.paths`** + `{{paths}}`, common URL variables, browser cookies by default, and template inventory skip reasons — still not full Nuclei (no dns/raw/dsl/cluster payloads).

| Practice | Detail |
|----------|--------|
| Safety | `"safetyMode": "safe"` is enough for GET/HEAD templates; write verbs need `"active"`. Blocked in `--safe` CLI. |
| Custom pack | Point **`templatesDir`** at a folder of `*.yaml` (or drop files in `nuclei-templates/` beside the exe / `%TROWSER_NUCLEI_TEMPLATES%`). Set **`includeBuiltinTemplates`: false** to run only your pack. |
| Multi-host | Pass **`targetUrls`** (array or comma-string). Each selected template runs per URL. |
| Base vs root | `{{BaseURL}}` includes the path of each target; for origin files (`.env`, `.git`) use **`{{RootURL}}`** or pass origin-only URLs — otherwise `/marketplace/.git/HEAD` misses the real leak. |
| Filters | **`tags`**: array or `"exposure,custom"`. **`severity`** (alias `minSeverity`): minimum severity. Empty match → 400. |
| Preflight | `GET /api/security/nuclei-templates` → `compatibilitySummary` + `skippedTemplates[]` before scanning a downloaded pack. Built-in YAML is **not** on GitHub under names like `env-file.yaml` — use inventory, don’t raw-fetch from nuclei-templates by filename. |
| SPA-focused | Embedded probes use **`{{RootURL}}`** for origin files. Tag filter **`tags: "exposure"`** (omit **`legacy`**) for Angular/React-oriented sweeps; add **`legacy`** when you want PHP/Apache/IIS/docker checks too. |
| Cookies | Default **`includeBrowserCookies`: true** — log in first for session-gated paths. |
| Output | `estimatedHttpRequests`, `templatesSelected`, `httpRequests` (not `verboseTrace`). Findings register into the chain feed (`source=nuclei`). |

Example — app pack + builtins across two origins:
```json
{
  "safetyMode": "safe",
  "targetUrls": ["https://app.example", "https://staging.example"],
  "templatesDir": "C:/sec/nuclei-app-pack",
  "includeBuiltinTemplates": true,
  "tags": "exposure,custom,misconfig",
  "severity": "low"
}
```
Scripting: `RunNucleiScan` / `AssertNucleiClean` / `PrintNucleiReport` accept the same options.

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
- Captures IDs from query parameters (e.g., `?productId=1`, `?artist=1`, `?cat=2`) and `*Id` / `*_id` names, plus short query keys whose values look like numeric object refs (cache-buster params such as `utm_*` are skipped).
- Reporting fields: `kind`, `value`, `source`, `paramName`, `type`, `contextUrl`.
- `suggestedBoundaryTests` emits ready-to-use `authz/boundary` configs: `urlTemplate`, `parameter`, `authorizedValues`, `unauthorizedValues`, `reason`. Placeholders use braces (`{id}`, `{artist}`), not percent-encoded `%7B…%7D`.
- You can POST a suggestion object directly to `authz/boundary`, or map `urlTemplate` → `endpoint` / `url`. Boundary parsing decodes `%7B` / `%7D` in templates automatically.

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

### Live Authz Shadow — ambient BAC testing

Instead of (or alongside) the manual `authz/*` sequence above, the **Live Authz Shadow** watches
normal browsing traffic and cross-identity replays it through registered peers. Replay strips
the owner's `Cookie` and `Authorization` (and cache validators). The peer browser sends its own
`Accept-Encoding`; the body is decompressed before compare. `fetch()` from `execute-js` is not
browser traffic and is not replayed. When the owner call carried `Authorization` or another auth
header, the shadow installs the **peer's** current value from the peer's own requests and from
the peer's `localStorage` / `sessionStorage`. `peerAuthApplied` is `cookie`, `bearer`, `both`, or
`none`. A denial with `none` is `Inconclusive`, not a correct deny. A 200 with the same body, when
the owner request carried a cookie or `Authorization`, is `ConfirmedLeak` (missing authentication),
not a public page. An HTML shell, and a request the owner made with no credential, can still
recommend public. Each result also carries `ownerStatus`, `peerStatus`, `ownerBodyLength`,
`peerBodyLength`, `peerFinalUrl`, `peerError`, and `ownerTokenCount`. A missing owner body is
`ownerBodyMissing` and is not scored as different content.

| API / MCP tool | Purpose |
|---|---|
| `GET`/`PUT /api/authz/model` · `browser_authz_model` | Read/declare per-`(method, urlTemplate)` intent — sensitivity (public/internal/sensitive) × ownership (shared/perUser/perTenant/roleGated) — and identity role/tier/ownerTags for a host. `seed:true` heuristic-prefills from the attack surface map. Per-user nouns (`/order`, `/account`, `/cart`, `/basket`, …) stay sensitive even when auth was not observed. Paths with no public-content noun are left unclassified rather than marked public. |
| `POST /api/authz/shadow` · `browser_authz_shadow` | `mode:"enable"` (with `safetyMode`, optional `peers`) turns on ambient replay; `status`/`results`/`clear` read state; `export`/`import` save and resume the result log plus access models. Off by default — GET/HEAD/OPTIONS/QUERY replay at every mode, including `passive`. POST/PUT/PATCH/DELETE need `active` or `aggressive`. `skippedBySafetyMode` counts successful writes that were not replayed. `skippedResourceType`, `skippedNonSuccess`, and `skippedThirdParty` count the other deliberate skips. `replayFailures` counts peer errors. |
| `POST /api/authz/coverage` · `browser_authz_coverage` | Cross-references the access model, the attack surface map, and shadow results. `testedPercent` is classified and/or tested, not a security score. Findings are grouped by verdict. `intentAlignment` is computed when coverage is read (`violation`, `consistent`, `unresolved`, `needs-classification`, or `unclassified`). Classifying a resource in the Live Authz Shadow dialog updates the next coverage read. Host keys collapse `:443` and `:80`. Returns JSON + Markdown. |

**Verdicts** (PascalCase on the wire, including `mode: "export"`; filters accept either case): `ConfirmedLeak` (peer body contains an owner token — set `ownerTags`, or let an authenticated user JSON / `/me` / `/profile` response harvest them), `BolaSuspected` (peer got a near-identical 2xx body), `SameShapeDifferentData` (same JSON shape, different values), `NeedsReview`, `FilteredResponse` (**different content — not proof the peer was scoped**), `ProperlyDenied` (only when the peer credential was actually sent), `Inconclusive` (compressed or binary body, missing owner body, or a read denial with `peerAuthApplied: none`), `ReplayedWrite` (a collection create where both identities got their own success — `peerMutated` is true; shown in amber, not as a denial), `PeerUnauthenticated` (that write ran with `peerAuthApplied: none`). A 2xx write whose path names an object (`{id}`) is `BolaSuspected`, including when the only body difference is an id.

A JSON or API 2xx is replayed even when Chromium labels the resource type `Other`. Scripts, stylesheets, fonts, and decorative images stay skipped. Long hex object ids in a path become `{id}`. `htmlShell` is set only when the body hash matches a different route; a unique page that is identical across the two sessions is an identical public document.

Coverage compares those verdicts to the model's expected outcome **at read time**. A near-identical body on a resource declared public/shared is `consistent`. The same body on a per-user resource is a `violation`. Different 2xx content on a resource that should have been denied is `unresolved`: do not treat it as a pass. Read status and lengths before accepting a verdict. `nextActions` calls out `peerMutated` writes and a `FilteredResponse` whose peer credential was applied.

**Classification** stays in the Live Authz Shadow dialog. It does not open the AI Assistant. An interesting verdict (`ConfirmedLeak`, `BolaSuspected`, `SameShapeDifferentData`, `ReplayedWrite`) on a resource without a human or AI answer is listed under **Needs classification**, one row per endpoint (several peer replays of that endpoint share the row). A heuristic seed is not an answer. A duplicate HTML shell is the same document as another route and is not a second row. An authenticated create and a list whose bodies already differ recommend per-user. An identical public document recommends public. Apply keeps the answer for this run, the endpoint leaves Needs classification, and the next coverage read uses it. It is not written into the access-model file, so a restart drops it. **Classifications** reopens this run's answers so they can be changed. **Export** and **Import** are how a copy survives. `mode: "clear"` drops the result log and this run's classifications. The dialog's **Clear results** also stops the shadow. `FilteredResponse` is not queued for classification; use coverage's compare line and the evidence fields instead. Skip reasons stay on the access model after clear.

**Resume later:** **Export** and **Import** on the Live Authz Shadow dialog write and read the same JSON file (results plus access models). Import asks whether to replace the current result list or add to it. The same bundle is `POST /api/authz/shadow` with `mode:"export"` (optional `path`) and `mode:"import"` (`path` or `bundle`, `replaceResults:true` to replace the in-memory log). A human or AI classification already on disk is not replaced by a heuristic from the file.

**Recommended flow:** spawn or start a peer (`POST /api/peer/spawn` with `{ "session": "attacker" }`, or `Trowser.exe --session attacker --api-port 6924` + `POST /api/peer/register` with `baseUrl` `http://localhost:6924`, not `127.0.0.1`). For IDOR probes from a single driver instance, `POST /api/fetch` also accepts `identityOverride: { "peer": "attacker" }` or a captured `identity` name — server-side only, jar unchanged. Enable the shadow (`mode:"enable", safetyMode:"safe", peers:["attacker"]`) before browsing. An anonymous peer answers "does this require a login?" A second account answers "is this object mine?" Log that account in through the peer's own browser, then browse. File a row when the reason names an email or a user id, or when a logged-in owner's 200 came back with `peerAuthApplied: none`. A 401 with `none` means log the peer in. Set `ownerTags` for emails and user ids, not record ids. Classify the rows in the Live Authz Shadow dialog, then pull `browser_authz_coverage`. A host with no replay results is not a clean app. Check `skippedBySafetyMode` before assuming writes were compared. Raise `safetyMode` to `active` only when replaying POST/PUT/PATCH/DELETE is intended.

```text
Trowser.exe --session attacker --api-port 6924
POST /api/peer/register  { "name": "attacker", "baseUrl": "http://localhost:6924", "apiKey": "<peer key>" }
POST /api/authz/shadow   { "mode": "enable", "safetyMode": "safe", "peers": ["attacker"] }
# Log the peer in as the other user. Browse one public GET and one per-user GET in the owner window.
POST /api/authz/coverage { "host": "<page host>" }
# File only rows whose reason names an email or a user id, or a 200 the peer got with no session.
```

---

## Phase 3 — Active Testing

### XSS Testing

**Pick the tool**

| Goal | Endpoint |
|------|----------|
| Active DOM XSS on the **current page** (query, hash, flows) | **`POST /api/security/dom-xss-audit`** (`safetyMode: "active"`) — default playbook-style bundle; turn off phases you do not need (e.g. `runClientSurface: false` for speed) |
| Reflected/stored XSS from **network-discovered** params | **`POST /api/security/xss-scan`** |
| One param, form field, or exact repro | **`POST /api/security/trace-input`** |
| Passive patterns only | **`POST /api/security/xss`** |

Do not treat a clean **`xss-scan`** as DOM XSS coverage. Names are easy to confuse: **`xss-dom-audit`** is an alias of **`xss-scan`**; **`dom-xss-audit`** is the separate DOM orchestrator (`browser_dom_xss_audit`).

**DOM XSS speed:** Start with **`dom-xss-audit`** + **`depth: "quick"`** (passive + dom-flow only, typically tens of seconds), or **`dom-flows`** `mode: "probe"` alone. Escalate to **`trace-input`** on the flagged param, then a full **`dom-xss-audit`** when you need all query keys + client-surface + hash traces.

**Reflected XSS** — use `trace-input` with `autoBypass:true` for automatic filter detection and bypass:
```
POST /api/security/trace-input {"target":"#search-input", "submit":"#search-btn", "submitAction":"click", "autoBypass":true, "safetyMode":"active"}
```
Note: `target` and `submit` accept CSS selectors only (not refs). With `autoBypass`, omit `payload`/`payloads` — the tool starts with `<script>alert(1)</script>` and escalates through 10+ alternative vectors if filtered.

**DOM XSS** — start with **`dom-xss-audit`** on the vulnerable page (covers passive + dom-flow + query/hash traces). Drop to **`trace-input`** when you need one param, a form control, or a custom payload:

```
POST /api/security/dom-xss-audit {"safetyMode":"active","runClientSurface":false,"confirmExecution":true}
POST /api/security/trace-input {"source":"url-query", "queryParam":"default", "autoBypass":true, "monitorSinks":true, "confirmExecution":true, "safetyMode":"active"}
POST /api/security/trace-input {"source":"url-hash", "autoBypass":true, "monitorSinks":true, "confirmExecution":true, "fragmentEncode":"none", "safetyMode":"active"}
```
**Reach vs confirmed XSS:** With `monitorSinks` (default `true`), two-phase tracing can report **sink reach** (`sinkReached`, often **medium**) without **confirmed execution** (`confirmedXss`, **critical**). That split is intentional for passive triage, but real DOM XSS on `innerHTML` / event-handler vectors needs the phase-2 **`__trowser_exec`** oracle — set **`confirmExecution": true`** (or `safetyMode: "aggressive"`, which enables it) whenever you are proving exploitability, not just mapping sinks. Without it, `<img onerror=…>` / `<svg onload=…>` that execute in the browser may still show `confirmedXss: false`.

For DOM XSS sources, `queryEncode` defaults to `"none"` (raw payload in URL). Use `fragmentEncode:"none"` for hash sources. Always test **both** query and hash vectors — server-side filters may block one but not the other.

**DOM flow graph** — prefer when you want every place attacker-controlled data becomes executable or security-sensitive DOM state (not a single-parameter probe):

```
POST /api/security/dom-flows {"mode":"observe"}
POST /api/security/dom-flows {"mode":"probe","safetyMode":"active","sources":["url-query","url-hash","post-message"]}
```

Add `"storage"` when the app is known to read `localStorage` into the DOM (the probe sets `trowser_probe` and reloads — it does **not** inject `innerHTML` itself). Chains include source, sink, mutation, consequence (`exec` / `nav-hijack` / `blocked-csp` / …), confidence (`canary` / `value-match` / `temporal`), and `tier` (`exploitable` / `hygiene` / `probe-artifact`). File **exec** only when `tier` is `exploitable` and the stack includes a **page-origin script URL** (not `<anonymous>` probe injection). `client-surface` embeds the same `domFlows` array.

**Typical runtime:** `observe` ≈ 1–5s; `probe` with several sources ≈ 10–40s depending on SPA settle.

**XS-Leaks** — browser-native differentials: can an attacker page distinguish two victim states?

**Hypothesis-only (no `states[]`):**

```
POST /api/security/xs-leaks {
  "safetyMode": "safe",
  "hypothesis": {
    "secret": "Search result reveals diagnosis",
    "urlTemplate": "https://app.example/search?q={value}",
    "hitValues": ["known-term"],
    "missValues": ["zzzznonexistent"]
  }
}
```

For **JSON POST** search (same API URL, body varies), use `bodyTemplate` + `contentType` — see [trowser-api-reference.md](trowser-api-reference.md) § POST /api/security/xs-leaks.

**Broader sweep first:** `POST /api/orchestrate/a14-other` runs smuggling, cache, redirect, and XS-Leaks steps together (Trowser Twelve table above).

First pass (browse the app, then scan with no `states`):

```
POST /api/security/xs-leaks { "safetyMode":"safe" }
```

Check `details.warnings`, `catalogMode` (`quick` vs `full`), and `sameUrlStates` — true only when URL **and** method **and** body/form match across states (same API path with different JSON POST bodies is **not** `sameUrlStates`). Timing/cache techniques are skipped when the full request target matches. **`autoStates`** picks **GET query** or **POST same-URL body** pairs from traffic when status or response length differs. If the top-level `message` says no distinguishable states but `details.stateValidation.credentialedDiff` is not `none`, trust **stateValidation** over `message`. If auto-states yield the **same URL without distinct captured session identities** (typical before login), the scan **returns immediately** with `nextActions` instead of burning the full technique catalog. **For SPAs**, prefer **JSON API endpoints** from the network log (e.g. `/api/users/one/admin`) over client route URLs like `/userprofile` — the HTML shell is usually identical across auth states, so load/error oracles on the route URL are structurally uninformative. **Default** (no `techniques`) runs a **quick subset**, not the full catalog — pass `"fullCatalog": true` for all safe-mode probes. **Typical runtime:** quick default on a local/lab host ≈ 30–90s; **full catalog on internet targets** often **3–15+ minutes** (latency × trials × technique count) — set `"budget": {"maxSeconds": 120}` for partial results, or filter with explicit `"techniques"`. JSON/API state URLs auto-prefer cache/size oracles; load/error techniques on JSON may show `applicability: low`.

Explicit state pair:

```
POST /api/security/xs-leaks {
  "safetyMode":"safe",
  "autoStates": false,
  "states":[{"label":"hit","url":"https://app/search?q=secret"},{"label":"miss","url":"https://app/search?q=zzzz"}],
  "techniques":["iframe-load","script-error","iframe-framecount"]
}
```

Uses a mocked attacker context (`https://evil.trowser.test/xsleak/...` by default; `attackerSite: same-site` for sibling-host experiments). For a declared **hypothesis** (`urlTemplate` + hit/miss values, or explicit `role: hit|miss`), Trowser validates server-side diffs, observes cookie delivery, plans techniques, then **screens** and **confirms** with a control miss — only `confirmationStatus: confirmed` becomes a severity finding. Response includes verdicts, `details.plan`, `details.stateValidation`, `confirmationStatus` per technique, optional `observeMode` vectors, `posture`, `browserModel`, `authModelNotes`, `chainFindings`, and `details.chainAnalysis` for confirmed leaks only.

Technique catalog includes load/error oracles (`img-error`, `script-module-error`, `track-error`, …), timing/cache (`performance-timing`, `event-loop-blocking`, `cache-timing`, `cache-prime-probe`, `connection-pool-exhaustion`), redirect/status (`fetch-redirect-type`, `status-bucket-oracle`, `redirect-count-oracle`), framing/popups (`iframe-framecount`, `popup-closed`, `window-open-length`, `history-length-delta`, `named-window-reuse`), and messaging (`postmessage-listen`, `broadcast-channel-probe`, `csp-violation-probe`). Active mode is required for cache priming, connection-pool/event-loop/cache timing, and popup/window probes.

Options: `includePosture` (default true), `postureInteractionProbes` (default on in `active` mode; off by default for hypothesis runs), `observeMode` (Phase 2 observation diff), `suggestOnly` (candidate hypotheses only). Leak-matrix calibration: `tests/regression/_calibration/README.md`.

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

### Auth Control Identifier
When a request carries many cookies, CSRF headers, and Bearer tokens, find which ones the server **actually validates** (and which are sent but ignored).

1. Browse and trigger the API call(s) of interest.
2. Open **Script Console → Endpoints** (Endpoint Probe), select the request(s).
3. Check **Auth Control Identifier**, set Safety to **Active**, optionally **test all headers**.
4. **Run** — results open in a table and are logged to the Script Console.
5. Look for **`ignored`** (e.g. `RequestVerificationToken` present but never checked) and **`presence-only`** (cookie must exist, value not validated). **`enforced`** means omit and one-char tamper both change the response.

Also available from the HTTP Request Editor (**Identify auth controls…**), REST `POST /api/security/auth-control-identifier`, MCP `browser_security_auth_control_identifier`, and scripting `RunAuthControlIdentifier`. Select multiple endpoints to see a consistency summary across them.

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

**HTTP outcome triage:** Use `responseStatus`, `responseStatusText`, `redirected`, `responseUrl`, and the `response` body snippet. If fetch fails in-page (CORS/network), check `responseStatusText` and the network log for the ACS POST.

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
`POST /api/security/session-fixation-scan` ( **`safetyMode: "active"`** ) logs in via the browser form when possible, compares **all** cookies before and after login, and flags **unchanged session-like** names (`connect.sid`, `session`, …). It **ignores** CSRF/analytics cookies (`XSRF-TOKEN`, `_ga`, …) and **does not** report fixation when login **issued a new** session cookie while an older cookie stayed stable. Non-session cookie names that still match pre-login values cap at **medium**.

Re-test with a **fresh** browser profile or `POST /api/clear-session` when you need to prove rotation on a specific cookie name (`cookieName` filter).

### Timing Oracle / User Enumeration
Compare `durationMs` from `/api/fetch` (or `/api/fetch/batch`) for valid vs invalid user identifiers. If timing varies significantly (>100ms), you have an oracle. Do not Stopwatch the REST round-trip — that includes gate wait and `delayMs`.

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

## Phase 7 — Verification & Reporting

Use after Phase 4c proofs or a playbook sweep when you need a final pass before handoff.

- Confirm exploitable XSS/DOM effects (`execute-js`, trace-input sink hooks, OOB callbacks)
- Re-run `chain-prove` / `verify-workflow` for critical and high findings; export evidence (`exportEvidence: true` or `POST /api/repro/capture`)
- Triage shadow mode and passive harvesters (console/network errors, source maps)
- Export VPX: **Settings → Experimental… → VPX Export…** or `GET /api/vpx/export` (spec: [`../securitykit/VPX/spec/VPX-1.1.md`](../securitykit/VPX/spec/VPX-1.1.md))
- Export journal and compile severity-rated report; capture `.trw` repros when the user wants reruns

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

### `/api/fetch/batch` — Response bodies
Bodies are **off by default** (`body: null`, `bodyLen` only). For IDOR / content comparison set `"includeBodies": true` (alias `"includeBody": true`) and optionally `bodyMaxChars` / `maxBodyChars`.

### `/api/load-test` vs `/api/fetch/batch`
- `load-test`: server-side, no browser cookies by default (use `useBrowserCookies:true`). Best for quick concurrency checks.
- `fetch/batch`: browser-context, includes cookies and session. Best for authenticated concurrent testing.

### `/api/fuzz` — Can Hang
Large payload sets with `pitchfork` attack type can run 4+ minutes without progress. Use `/api/abort` to recover. Prefer `/api/fetch/batch` for controlled parallel testing.

### `/api/security/discover` — SPA shells and SSO login gates
Unknown paths are compared to one invalid-path probe. **`spaMode` defaults to `true`:** HTML responses with the same status, title, and similar body length as that probe are excluded, and `baselineNote` says how many. Set `spaMode: false` to keep them; the note then warns that they match the baseline. API-shaped bodies (`json`, `xml`, `text/plain`) stay in `discovered`. When several of those are byte-identical to the probe, `baselineNote` says so — compare bodies before treating them as separate endpoints. A site that returns **404** for unknown paths has no baseline, so real pages are unchanged.

Shibboleth / SAML / OIDC apps often **302 every unknown path** to the same IdP URL (with unique `SAMLRequest` / `state` query params). Trowser fingerprints the invalid-path baseline redirect (host+path, query stripped) and filters matching 3xx responses automatically — they are not findings. Authenticate first if you need discovery behind the login gate.

### `/api/security/swaggering` — How to read the result

Pass `specUrls` when the document is not on a well-known path and Swagger UI has not loaded it into the network log. A host name that contains `swagger` is not treated as a spec. 404s on guessed spec paths are silent; a warning that mentions 401 or 403 means the spec exists but the session cannot read it.

`operations[]` is the coverage map. Do not stop on `message` alone: if `budgetExhausted` is true, rows with `outcome: "not-reached"` were not called. `autoScan` runs only at `standard` and `thorough`, and only against the catalog plus traffic already captured — not against a built-in list of product-search URLs. Shadow findings do not include the OpenAPI document itself.

Probes are sent with the browser cookie jar from the server. They are absent from `GET /api/network`. DELETE is omitted unless `includeDeleteMethods` is true. Default `depth` is `thorough` and blocks the API gate for a long time; set `depth` and `maxStepSeconds` on agent runs.

### `/api/security/nuclei-scan` — BaseURL vs RootURL
`{{BaseURL}}` keeps the path of each `targetUrls` entry. For origin-level files (`.env`, `.git`), use **`{{RootURL}}`** in custom YAML or pass origin-only URLs — otherwise `/app/page/.git/HEAD` misses the real leak (SPA HTML). Prefer body **word** matchers with status to avoid SPA false positives. Use **`{{RootURL}}{{paths}}`** with **`payloads.paths`** for swagger-style path lists. Check **`compatibilitySummary`** / **`skippedTemplates`** for templates that need full Nuclei.

### `/api/security/cookies` — HttpOnly and JS-set cookies
The audit reconciles jar cookies with **Set-Cookie** from the network log for HttpOnly/Secure/SameSite. Cookies set only via `document.cookie` may lack Set-Cookie history — use `execute-js` on `document.cookie` when you need that angle.

### `/api/security/csrf` — Needs Network History
Browse and submit forms first. The scanner only checks POST/PUT/PATCH/DELETE requests already in the network log. It won't detect GET-based state changes — test those manually.

### `/api/security/methods` — Misleading with SSO
Server-side methods testing doesn't carry browser cookies. 302 redirects to login may be counted as "allowed". Validate findings with authenticated `/api/fetch`.

### `/api/click` — Stale Refs After Navigation
After any navigation (including SAML SSO redirects), element refs become invalid. Use `byText` selectors instead of `ref` numbers.

### `/api/execute-js` — Field name, Promises, and fetch()
Body field is **`script`** (aliases: **`expression`**, **`code`** — same as many LLM examples). Do not confuse this with verify-workflow oracle steps, which use `"type": "expression"` for a different API. `ExecuteJs` **awaits Promises** returned from the script (async IIFEs, `.then()` chains); unsupported syntax fails with **500** — see the API reference. For HTTP probes, prefer **`/api/fetch`** or **`browser_fetch`**: structured status/headers/body and entries in the network log. Raw `fetch()` inside execute-js works when wrapped in an async expression, but ad-hoc fetches are not logged in `browser_network`. In Angular SPAs with Zone.js, **`browser_fetch`** is still safer than manual fetch in execute-js.

Do **not** pull JS bundles or source maps through execute-js `fetch()` — WebView2 often hangs until the 30s JS timeout even with an in-page `AbortController`. Use **`browser_fetch`** with `serverSide: true` (then search the body), or **`browser_security_js_audit`** / **`browser_security_secrets_harvest`** (`safetyMode: "active"`).

### Hidden injection surfaces (do not stop at observed params)
Captured traffic often uses one query key while the sink also accepts siblings. Before declaring “no SQLi/SSTI”:

- Fuzz sibling query names: `query`, `q`, `search`, `id`, `count`, `filter`, `term`, `keyword`, `dummy`, `maptitle`
- Probe a small header set when relevant: `x-product-name`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`
- For SSTI, try a **Content-Type matrix** (`text/plain`, `application/json`, `application/x-www-form-urlencoded`) — JSON-only traffic frequently misses engines that evaluate plain text
- Auto-scan now mutates common sibling query names; still run **one** targeted `sqli-scan` / `trace-input` / `ssti-scan` per high-value endpoint before closing

### Open redirect — HTTP vs DOM
**Server-side (HTTP 302 + `Location`):** Do **not** conclude a miss from browser `fetch` with default follow (you lose the `Location` header). Use `POST /api/fetch` with `"redirect": "manual"` or **`open-redirect-scan`**. Explicit `urls` / `endpointHints` / DOM-discovered redirect links outrank scaffold paths (`/api/goto?url=` style). When hints are set, scaffolds are skipped unless `includeScaffoldWithExplicit: true`. If the response includes `warnings` that a hint was not probed, treat the scan as incomplete.

**Client-side (DOM):** `open-redirect-scan` does **not** prove DOM navigation (`location.href`, `location.assign`, `window.open`) — there is no off-site `Location` header. **`client-surface`** / passive XSS may flag **DOM open redirect** as a **lead**; follow with **`trace-input`** on the real query param (e.g. `queryParam: "next"`). Default **`autoBypass`** uses XSS-shaped probes, which often fail app-side prefix checks (`startsWith("/")`, etc.) before the navigation sink runs. Until trace-input auto-selects redirect bypass payloads for navigation sinks, pass **URL-shaped** probes explicitly (protocol-relative `//probe-host/`, backslash `/\`, encoded slashes, `@`-trick) via `payload` or ensure bypass catalog covers nav sinks when `monitorSinks` lists `location.href` / `assign` / `replace` / `window.open`. Confirmed off-site navigation can appear as `sinks` with classification **`dom-open-redirect`** (distinct from HTTP `serverResponse.openRedirect`).

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
`POST /api/abort` cancels the gated operation’s `OperationCancellation` token. **auto-scan**, **attack-surface** API enrichment (OpenAPI/dev-artifact/JS hint probes), and nested injection scanners honor that token between steps and should unwind. Guarantees are **checkpoint-based** (not a hard kill of an in-flight socket). If the gate stays busy for minutes after abort, the current nested call may be ignoring cancellation — force-navigate / restart the instance as a last resort.

### Severity policy for agents (HIGH/CRITICAL)
Treat **HIGH/CRITICAL** as “needs proof” until corroborated:

| Class | Require before CRITICAL |
|-------|-------------------------|
| XSS | Sink reach **or** reflection + causal Dom — not residual markers alone |
| Command injection | Shell-output canary (`cmd-canary`) — `uid=` / `gid=` / Windows IP style output; not SQLi on `cmd`/`exec`. Browser **callback** hits and URL **reflection** are **info** (client-side signal), not server RCE |
| File upload | Persistence / readback oracle — HTTP 200 on multipart to a render/SSTI sink is **not** upload RCE |
| SQLi | Error signature, confirmed boolean pair, or auth-bypass heuristic — not a single length delta; use collapsed `findings` + `details.findingGroups` (payload catalogs), not one alert per payload |

When cmd-canary and SQLi both fire on the same parameter, **keep RCE** and drop the SQLi finding (class arbitration).

### False-positive triage checklist

Short checks before filing HIGH/CRITICAL from Trowser scanners.

#### Residual DOM (trace-input / XSS)

**Symptom:** `verdict: critical` / “Confirmed DOM XSS” while `payloadReachedSink: false`, `payloadReflected: false`, and often HTTP 404 (url-query fallback after form filtering).

**Cause:** Prior stored/reflected probes left `onerror` / markup in the page; Dom markers matched ambient content for a *different* probe.

**Symptom (inert script via innerHTML):** `dom.context` includes `script-content`, `dom.dangerous: true`, but `sinks.executionConfirmed: false` and `hitCount: 0` for a `<script>…</script>` payload. Browsers do not execute `<script>` inserted through `innerHTML`.

**Triage:**

1. Ignore CRITICAL when `payloadReachedSink: false` **and** no reflection for *this* payload.
2. Prefer `info` / residual wording in `verdict.summary` — do not file as confirmed XSS.
3. Re-test on a clean session or after clearing stored comments; require sink hit or reflection before escalating.
4. For inert `<script>` DOM markers, treat as **unsanitized sink (HIGH)** until an **event-handler** vector or execution oracle confirms; use `autoBypass` (URL probes retry bypass ladders too).

API behavior: severity is capped to **info** for residual markers; inert script-content without execution is capped below CRITICAL; Dom.Dangerous is reconciled away on error statuses without sink/reflection.

#### Search box → API query (`trace-input`)

**Symptom:** `fetch`/`xhr.open` hit with payload in `?searchText=` / `?q=` but no DOM reflection or execution.

**Triage:** Expected form behavior — not XSS. Severity is **info** (classification `intended-search-request`). Escalate only if the API response or page reflects unsanitized HTML/JS.

#### `xss-scan` guessed hash params (`spa-common`)

**Symptom:** Multiple **DOM XSS** findings on `q` / `search` / `query` with `context: not found` and identical payloads.

**Triage:** Blind hash-param probes are no longer emitted by default. DOM findings require execution oracle, causal DOM markers, or dangerous HTTP reflection — not unrelated page XHR during navigation. If **`xss-scan`** is clean on a hash/query-heavy page, run **`dom-xss-audit`** (or **`trace-input`** on the real param) before closing DOM XSS.

#### `postmessage` active proof + blocked attacker iframe

**Symptom:** Critical finding from `innerHTML`/`setAttribute` with Swedish/English “content blocked” interstitial text.

**Triage:** Browser error-page chrome when `evil.trowser.test` fails to load — not the app. Critical active proof requires a **trusted** `MessageEvent` delivered to the parent, not sink noise alone.

#### `postmessage` synthetic screen vs active confirmation

**Symptom:** Medium/tentative “Synthetic postMessage screening reached a sink” or hygiene findings, but no critical.

**Triage:** Expected — synthetic `dispatchEvent` uses spoofable `origin` (`isTrusted: false`). Re-run with `safetyMode: active` (mocked `child-iframe` under `https://evil.trowser.test/pm/{runId}/…`). Critical requires **trusted delivery + canary in sink snippet**. Synthetic screening uses **control vs bypass origin differentials** (bypass-only → tentative; control-only → low).

#### `postmessage` static hygiene vs active confirmation blocked

**Symptom:** `findings[]` still listed a **high** “no origin check” hygiene row, but every `techniques[]` row for that `listenerId` is `blocked` / `confirmationStatus: none`.

**Triage:** After `safetyMode: active`, hygiene rows for that listener are **demoted** (typically **info**), with `extra.activeConfirmation: "blocked"` and `extra.caveat` summarizing technique count. Static **`runtime-origin-compare`** (e.g. `e.origin === location.origin`) avoids false **none** when CDP returns full handler source. Report **critical** only from active `sink-reached`; read `caveat` if you paste `findings[]` alone.

#### `postmessage` outbound OAuth correlation

**Symptom:** High “OAuth-shaped data sent via postMessage” only when network log already has authorize/callback traffic.

**Triage:** Wildcard `postMessage` of non-secret UI data stays hygiene. Outbound high findings require OAuth-shaped payload **and** session OAuth traffic correlation.

#### `oauth-flow-test` flowBreaker

**Symptom:** Browser navigates real `/authorize` URLs; may consume an auth code.

**Triage:** Opt-in `flowBreaker: true` (requires `active`). Bounded by `maxBrowserSteps` (default 2). HTTP-only probe results stay tentative until browser landing oracle confirms query/fragment/postMessage/storage. **SAML ACS POST** (`saml-acs-post`) is reported for orientation — use **`saml-decode` / `saml-replay`**, not OAuth token semantics.

#### `oauth-flow-test` vs SAML / mixed federation

**Symptom:** `errors` says no OAuth authorize flow, but the app uses Shibboleth/SAML or hybrid login.

**Triage:** After SSO browse, call **`wait-for-final-navigation`**, then **`oidc-analyze`** and **`oauth-flow-test`** with **`passiveOnly: true`**. Read **`dossier`** first (binding, client_id, artifact handles, **`nextActions`**). Discovery may be absent — that is not a blocker. Re-run with **`passiveOnly: true`** and read **`authSignals`**. SAML signals route to **`saml-decode`** / **`saml-capture`** / **`saml-replay`**. BFF login (**`binding: bff`**): pass **`issuer`** to **`oidc-analyze`** (login UI host ≠ issuer); test session cookie and peer identity, not front-channel probes. Active code replay and redirect_uri probes need **`safetyMode: active`**. Federation info finding when OAuth and SAML share a session.

#### Echo-boolean SQLi

**Symptom:** Many “blind boolean” highs that differ only because the form echoes the payload string (`1 AND 1=1` vs `1 AND 1=2`).

**Triage:**

1. Prefer `blind-boolean-confirmed` (noise-stripped hash split after payload-echo neutralization) or SQL error signatures.
2. Treat length-only differentials without confirmation as tentative.
3. Use `details.findingGroups` / `extra.payloads` — one group per `(endpoint, param, class)`, not one finding per payload.

#### Sparse-traffic SQLi/XSS scaffolds (`ALWAYS_PROBED` templates)

**Symptom:** High or critical SQLi on generic paths such as `/api/file?path=` or `/search?q=` when the app never used those routes (common on SOAP/REST demos with a WADL but sparse browser traffic).

**Triage:**

1. Treat titles prefixed with **`Hypothesis (scaffold):`** and severity capped at **medium** as leads — not filing-grade until the path appears in the network log or `attack-surface`.
2. Browse the real flows first; re-run `auto-scan` or targeted SQLi on captured URLs.
3. Do not let a clean **cookie audit** override **storage** / `GET /api/session/identity` when the SPA keeps JWTs in `localStorage`.

#### Wrong-difficulty / wrong-method URL

**Symptom:** Scanner probes GET `?id=` while the live form is POST (or the opposite difficulty path on lab apps).

**Triage:**

1. Snapshot the live form / `attack-surface` first; use cloned sibling fields (`FormProbeCloner` / `{ url, param }` shorthand).
2. A 404 or CSRF rejection on every payload is **inconclusive**, not “safe”.
3. Do not treat homepage body equality after traversal as a bypass (see path-filter-bypass notes below).

#### HTTP request smuggling (false positives)

**Symptom:** Medium/high “smuggling” from Via, CF-Ray, duplicate Content-Length 200, or TE-TE HTML body differences on a dynamic page.

**Cause:** Passive analysis used to treat proxy/CDN presence as risk; TE-TE compared exact response bodies (CSRF tokens, timestamps); CL-CL “accepted 2xx” is common CDN hygiene, not proven front/back disagreement.

**Triage:**

1. File a bug **only** when `verdict` is `confirmed` and `confirmationMethod` is `differential-response` (repeated canary 404).
2. Timing stalls, TE obfuscation acceptance, HEADER not-400, and duplicate CL are **architecture notes** (`unconfirmed-architecture`).
3. Audit-all / A02 / A14 must not list Via or CF-Ray as vulnerabilities. Ambiguous **response** framing (both TE and CL) is the only passive elevate.
4. HTTP/2-only ALPN (`infrastructure.httpVersion` / `alpn`) means HTTP/1.1 desync may not apply — fingerprint, don’t attack H2.CL/h2c (not implemented).

Quicktest **3 HttpSmuggling** asserts confirmed-only. One scan per origin is enough.

#### DOM flows storage probe (self-calibration artifact)

**Symptom:** `mode:"probe"` with `"storage"` (or the full default source list) reports `exploitableChainCount: 1`, `consequence: exec`, stack `at <anonymous>:1:…`, value `trowser_probe=…` / `trowser_canary_…`, on a page with **no** app script reading storage.

**Cause:** Previously Trowser injected the canary into `innerHTML` during the storage probe; the runtime sensor treated that as a victim flow.

**Triage:**

1. Ignore **exec** when `tier` is `probe-artifact` or stack has no `https://` page script line.
2. Require `tier: exploitable` **and** page-origin stack before “Confirmed executable DOM XSS”.
3. On static pages, `storage`-only probe should report **zero** exploitable chains after a fix — use `observe` first, add `storage` only when the app uses storage-driven rendering.

#### XS-Leaks same-URL / timing noise

**Symptom:** `autoStates` / `identity-pair` with **identical** `states[].url`, `performance-timing` `probable`, or partial chain “XS-Leak + CORS → mass data breach” with no real state difference.

**Cause:** Comparing one URL to itself measures network jitter, not attacker-observable state. Auto identity pairs without cookies do not change the victim response.

**Triage:**

1. Read `details.warnings` and `stateGeneration` — if `sameUrlStates: true`, timing techniques were skipped or results are not filing-grade.
2. Do not escalate **probable** timing on identical URLs; browse authenticated APIs or pass explicit distinct URLs.
3. Capture identities with `browser_identity_capture` on the target host before `autoStates`.

#### Auto-scan hung / partial

**Symptom:** Gate stays `busy` for many minutes on `scanDepth: quick`.

**Triage:** `maxStepSeconds` defaults apply (quick≈120s, standard≈300s, thorough≈900s). On expiry expect `budgetExhausted: true` and partial findings — not a hang. Use `POST /api/abort` if a nested call ignores cancellation mid-socket.

#### Fail-open `fail-open-after-error` (removed)

**Symptom:** Older docs or chain templates mention **`fail-open-after-error`** or POST success after a **mock HTTP 500**.

**Triage:** That branch was removed — a WebView mock never faults the server, so the retry always looked like fail-open. Current categories: **`fail-open-unauthenticated`**, **`fail-open-invalid-token`** only. `includeAfterError` on the API is a **no-op** (compatibility).

#### Workflow step-skip replay in the same session

**Symptom:** High **`workflow-step-skip`** after checkout/confirm when you already completed the flow in this browser.

**Triage:** Replaying the **captured** body with session cookies is recorded as an **info** observation (`workflow-replay-accepted`), not a finding. Only **minimal body** `{}` acceptance files **medium** — confirm with a **fresh session** (no prior step cookies) before filing high.

#### Cmd-canary OOB / reflection vs RCE

**Symptom:** **`rce-indicator`** high from callback URL in the response, or OOB hits from unrelated blind XSS/SSRF in the network log.

**Triage:** **`callback-reflection`** and browser **`callback-browser-hit`** ( `/probe-cmd-*` only) are **info**. **`command-injection`** with weak strings (`Linux`, `/bin/` in stack traces) is **medium**; reserve **critical** for `uid=` / `gid=` / clear shell output. Timing tier requires a **confirmed** second slow sample vs baseline.

#### Session fixation on CSRF or analytics cookies

**Symptom:** **`session-fixation`** on `XSRF-TOKEN`, `_ga`, or stable cookies after login issued **`connect.sid`** (new).

**Triage:** CSRF/analytics names are excluded; unchanged pre-login cookies are ignored when a **new** session-like cookie appeared at login. File fixation only on the cookie that **should** have rotated.

#### Single-sample timing (ReDoS, deserialization, Next.js RSC sleep)

**Symptom:** One slow response → **`redos-suspected`**, deserialization timing, or Next.js **`flight_sleep`**.

**Triage:** These probes **replay** control + attack once before filing. ReDoS confirmation uses a **same-length benign** control string (no `!`). Do not escalate on a single transient latency spike you reproduced manually once — require the scanner’s confirmed delta or reproduce twice yourself.

#### SSTI error signature already on the page

**Symptom:** High SSTI “error signature” on every payload when the baseline HTML mentions `handlebars`, `twig`, or template engine names.

**Triage:** Signatures present in the **baseline** are subtracted; escalate only when the indicator is **new** on the probe response (or use arithmetic **`49`/`56`** confirmation).

### `cmd-canary` request shape
`{ "param": "command" }` is not a request and returns 400. Put `{{INJECT}}` (or `§INJECT§`) in `request.url` or the body. PowerShell prefers `{{INJECT}}`.

```json
POST /api/security/cmd-canary
{ "safetyMode": "active", "request": { "url": "https://target.example/api/file?path={{INJECT}}" } }
```

### `jwt-forge` algorithm
Set `algorithm` (for example `"none"`) or `modifications.header.alg`. `algorithm: "none"` also strips the signature unless `stripSignature` is explicitly false. A payload-only `modifications` object leaves the original `alg` unchanged.

```json
POST /api/security/jwt-forge
{
  "safetyMode": "active",
  "baseToken": "<jwt>",
  "algorithm": "none",
  "modifications": { "payload": { "user": "admin" } }
}
```

The same alg change is `modifications.header.alg` plus `stripSignature: true`.

### `GET /api/network` field names
Entries expose **`statusCode`**. `?summary=true` returns `count`, `errors`, and `summary` (one string per request, starting with `#id`) and omits `entries`. **`GET /api/network/{id}`** returns that one entry with headers and any captured body. `responseBodyCapturedChars: null` means the body was never stored; `POST /api/fetch` is a new request, not that capture. A `no-csrf-token` result is not final when the captured call sent a custom header (`X-CSRF`, `X-Requested-With`, other `X-*`): the scanner replays without those headers before calling the endpoint vulnerable.

### `sqli-scan` shorthand and PowerShell markers
`{ "url", "param" }` injects literal `§param§` into the query and retains sibling query params already on the URL. When a matching GET form is on the current page, missing siblings (including submit buttons) are cloned from the DOM. In PowerShell prefer `{{param}}` inside a full `request.url`, or JSON `\u00A7param\u00A7`. Never hand-build markers through `UriBuilder` — percent-encoding breaks marker detection.

### `trace-input` response shape
Auto-bypass responses expose **`verdict`** (alias of `worstVerdict`) plus `effectiveTrace.verdict`. Do not treat a missing top-level `verdict` on older builds as “null finding” — read `worstVerdict` / `effectiveTrace`. Form probes surface **`injection.formInteractionFailed`** / **`formInteractionFailureReason`** when the target selector matched zero elements. **`autoBypass: true`** (default) shares the same two-phase confirmation path as explicit payloads; with `monitorSinks` + `twoPhase`, a caller-supplied `<script>` primary is upgraded to an event-handler confirm when reach hits `innerHTML`. **`reachMap[].knownBenign`** marks nav active-link `location.href` echoes (query canary noise). **`autoBypass`** wall time is budgeted (not N× full `timeout` per vector).

### Playbook / auto-scan budgets
Standalone **`auto-scan`** applies a depth default wall-clock budget (`quick`≈120s, `standard`≈300s, `thorough`≈900s) via `maxStepSeconds` when omitted — expect `budgetExhausted: true` and partial results rather than an indefinite busy gate. Full `a05-injection` recommends ~1800s. For LLM/agent sessions prefer **`a05a-injection-core`** (then `a05b` / `a05c`) or **`depth: "llm"`** (aliases: `agent`) with a 120–300s budget — warnings stay informational instead of pushing multi-hour caps. With `budget.honorRequested=true` and a short cap on full A05 (e.g. 90s), the playbook switches to an **injection-fast** profile (cmd/xss/sqli only).

### `/api/clear-all` — Destructive
Clears form fields and configuration. Never call on an SP config page without the `preserve` parameter.

### PowerShell `ConvertTo-Json`
Default depth is 2. Always use `-Depth 5` or higher for nested request bodies. For journal entries, raw JSON strings work more reliably than `ConvertTo-Json`.

### `/api/security/path-filter-bypass` — False Positives with Traversal Payloads
The `backslash-normalize` and `encoded-dot-dot` payloads (e.g., `/admin/..\`) resolve to the site root via URL normalization, producing a status change (403→200 or 404→200) that may not be a real bypass. Always verify: fetch the bypass URL and compare the response body against `/` — if they match, it's a false positive. The `content-differential` indicator confirms only a status difference, not that different protected content was accessed.

### `/api/security/harvest-ids` — Empty or sparse results
Browse pages that return **200** with object-like query or path IDs first; entries with status ≥400 are skipped. A single numeric path id on a 2xx response (`/api/users/id/1`) is enough for a `suggestedBoundaryTests` entry. OpenAPI documents (`swagger-json`, bodies with `"openapi"` / `"swagger"`) are not treated as object-ID sources — example values and `operationId` strings are skipped so they do not crowd out live API ids. Third-party hosts (maps, CDNs) are excluded when the page host is known. If you only see static assets in the log, harvest returns few IDs — drive a search/list/detail flow, then retry. Use `"includeDom": true` (default) for `data-*` attributes.

### `/api/security/auth-bypass-pivot` — Requires 401/403 in Network Log
The tool auto-detects retest candidates from the network log. If you haven't browsed any pages that return 401/403, it reports `endpointsRetested: 0`. Browse protected endpoints first (e.g., navigate to `/admin`).

### `/api/authz/boundary` — Request shape
Required: **`parameter`** plus a URL template on **`endpoint`**, **`url`**, or **`urlTemplate`** (with `{parameter}` or `{id}` placeholders). Values: **`authorizedValues`** / **`unauthorizedValues`** (aliases **`authorizedIds`** / **`unauthorizedIds`**). JSON arrays may use strings or numbers (numbers are coerced to strings). Templates with `%7B` / `%7D` are decoded on input. Prefer copying `suggestedBoundaryTests[]` from `harvest-ids` verbatim.

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

### Client-side surface (browser-native)

After browsing key flows, map the live DOM/runtime before guessing which browser-side class to test. Quicktest **`2 ClientSurface`** prints the same checklist.

```
POST /api/security/client-surface
```

Read **`risks[]`** first. Each row is a clue, not a finding:

- **`pursue`** — the precondition is on this page. Run that row's `followUp` (postMessage audit, DOM XSS audit, CSTI, gadget chains, and so on).
- **`lead`** — something is present, or the sensor did not see the load. Do not skip it on an empty log.
- **`manual`** — client-side authorization and frontend business logic. This map cannot clear them.
- **`dismiss`** — skip that scanner for this page. A dismiss is not a vulnerability, and it does not cover routes you have not opened.

`nextActions` repeats the pursue, lead, and manual follow-ups. `riskSummary` is the four counts. The map does not itself run XS-Leaks, gadget-chain probes, CSTI, or the postMessage audit.

```
POST /api/security/postmessage {"safetyMode":"safe"}
POST /api/security/client-prototype-pollution {"safetyMode":"active"}
POST /api/security/gadget-radar {"action":"read"}
POST /api/security/gadget-chains {"safetyMode":"active"}
```

Run those when the matching `risks` row says `pursue` or `lead`. When **XSSI** is **lead**, run **`browser_security_xssi_scan`** (or quicktest **`2 XssiScan`**) after browsing JSON/JSONP API traffic. Enable Shadow audit **`runtime`** so sinks, **gadget-read** (missing-global) events, and message listeners accumulate while you click. Use **`gadget-chains`** after browsing to run tailored clobber / client-PP / dom-flow probes; **`gadget-radar`** alone ranks execution-driven gadget candidates from the buffer. Prefer `monitorSinks: true` on `trace-input` — results include the instrumented sink inventory even when `hitCount` is 0 (`zeroResultReason`).

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
| `peerFetch` | Fetch via a peer Trowser session |
| `effectCheck` / `expression` | Evaluate a JS expression or compare captured variables (`equals`, `contains`, `matches`) |
| `domDiff` | Interactive-element ref generation changed after trigger |
| `networkMatch` | Network log slice matches URL/status criteria |
| `cookieDelta` / `storageDelta` | Cookie jar or Web Storage gained a named key |
| `screenshotCompare` | Visual diff vs setup screenshot (`markBeforeTrigger`) |
| `sinkReached` | Runtime sensor saw a sink after trigger (`sink`, optional `contains`) |
| `messageDelivered` | Runtime sensor saw a `message` event (`origin`, optional `contains`) |
| `prototypePolluted` | `Object.prototype[key]` holds the expected canary |
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

### Repro Capture & Fix-Verification Cycle

Generic repro (not security-specific) uses the same workflow engine as `verify-workflow`. Capture a `.trw` from the checkpoint trail, or re-run a bundle that `exportEvidence: true` already wrote.

**Capture from the session since a checkpoint:**
```
POST /api/repro/capture {"checkpointId":"<id>","path":"C:\\repros\\finding.trw"}
```

**Verify (k runs, clean session, optional identity):**
```
POST /api/repro/verify {"trwPath":"C:\\repros\\finding.trw","runs":3,"clearSession":true,"safetyMode":"active"}
```
Returns `reproducible` | `flaky` | `not-reproducible` plus a pass `rate`.

**Rerun a saved evidence bundle after a fix:**
```
POST /api/repro/verify {"bundlePath":"<path-from-export>","expect":"not-reproducible","safetyMode":"active"}
```
Re-executes the proof workflow. If the vulnerability is fixed, the oracle fails and `verdict` is `not-reproducible` (or `inconclusive` if `expect` does not match).

**Fix-verification workflow:**
1. Create and run a verify-workflow that proves the vulnerability (`exportEvidence: true` writes the bundle)
2. Or capture a `.trw` from journal actions since a checkpoint
3. Developer applies the fix
4. Re-run with `expect: "not-reproducible"` — if the oracle now fails, the fix works
5. Include both runs in the security report as before/after proof

### VPX Export (Assessment Package)

Export the full security assessment as a machine-readable VPX (Vulnerability Proof eXchange) package:

- **GUI:** **Settings → Experimental… → VPX Export…** (writes a `.vpx.json` file from the live session). **VPX Import…** merges a saved document back into the session for continued dedup / proof work.
- **REST:** `GET /api/vpx/export`
- **MCP:** `browser_vpx_export`
- **Spec:** [`../securitykit/VPX/spec/VPX-1.1.md`](../securitykit/VPX/spec/VPX-1.1.md)

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

### Web cache testing

Once tech-stack (or cache-map identify) says a cache is in play, the first confirmation is **live-key error pollution**, not query-string mapping.

1. **Identify (passive)** — `POST /api/security/tech-stack` `data.cache` (`detected`, `documentStatus` HIT/MISS/DYNAMIC/no-store). A cache is not a finding.
2. **Map (safe indication)** — `POST /api/security/cache-map`. Unique `?trowser_cb=` busters only. Answers “what is in the key?” without intending to poison the live slot.
3. **Live-key pollution** — `POST /api/security/cache-pollution-scan` with `safetyMode: "active"`. Same URL throughout; **no** `trowser_cb`. Find a header that forces a miss on the clean URL (header reached origin but did not split the key), combine it with error-inducing headers, then a fully clean GET. Confirmed `cache-error-stored` means other users may receive that error. If no miss-forcing header is found, stop — do not fall back to query pollution.
4. **Other confirmations** — `cache-poison-scan` with the same `bypassHeader` for unkeyed *reflection*; `cache-deception-scan` on authed paths.

Auto-scan may run cache-map (`includeCacheMap`, default true) and deception; pollution and poison stay out of auto-scan. A14 (`active`) runs identify → map → pollution → poison (feeds `bypassHeader`). Pollution and poison are skipped when identify and map find no cache.

**Orchestrated reports:** cache-map rows are **indications** — orchestration markdown and `severityHistogram` use capped severities (typically **info/low**) and group duplicate normalization probes. Treat elevated **scanner-weighted score** or `claimedSeverity` as triage hints only until `cache-pollution-scan` confirms live-key storage.

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
- **Socket authz:** `POST /api/security/websocket-authz` — sends one captured frame on a peer's already-open socket. Live Authz Shadow records the socket as a coverage gap and does not replay it as HTTP. The Live Authz Shadow window has **Test socket authz** beside each open socket.

### Server-Sent Events (SSE)

Browse or drive streams first. Trowser captures events via CDP `Network.eventSourceMessageReceived` (native `EventSource`) **and** `Network.dataReceived` chunks (`fetch()` + `ReadableStream`). Network rows are logged at response headers (`?eventStream=true`), without blocking on the full body.

- **SSE audit:** `POST /api/security/sse-audit` — CORS/credentials screening, sensitive data in event payloads, dangerous `EventSource` handlers, and optional active checks (unauthenticated subscribe, cross-origin proof, `Last-Event-ID` replay, peer fetch-direct). GET streams allow active reads at `safe` with tight caps; POST streams require `active`.
- **Costly ops:** long-lived `text/event-stream` responses surface as `costly-long-lived-stream` with `relatedProbe: sse-audit`.
- Live Authz Shadow skips replaying open event streams (avoids hanging on endless bodies); use the SSE peer check when two identities are registered.

### Build Regression Testing
After each new build, re-run the exact requests that previously caused 500s via `/api/fetch`. Compare status codes to confirm fixes and detect regressions.

### Shadow Mode as Passive Net
Enable Shadow at session start (off by default). Factory audits (XSS, Retire.js, Headers, Network, Console errors) catch 500s, console errors, XSS/CVE signals, missing CSP, credential patterns, SQL error signatures, and CAPTCHA answer leaks while you focus on targeted testing. Turn on WCAG (and other optional audits) in Settings → Experimental if you want those too. Check findings periodically with `GET /api/security/shadow`.

---

## Report Compilation
After testing, compile findings from:
- **`POST /api/security`** overview (or its modules: `js-libraries`, `headers`, `cors`, `xss`, `cookies`, `source-maps`, `storage`, `mixed-content`, `methods`, `discover`, `firewall-test`, `tech-stack`)
- **`POST /api/audit-all`** rollup when you ran page health
- Shadow audit categories (internal names like `security-headers`, `retire-js`, `xss` — map to REST paths above when citing reproduction steps)
- Attack surface inventory
- **Attack chain analysis** (`chain-analyze` confirmed and partial chains)
- **Chain-prove results** (proven chains with per-step evidence)
- **Verify-workflow proofs** (custom proof workflows with oracle verdicts)
- **Repro bundles** (`/api/repro/verify` on a captured `.trw` or `exportEvidence` bundle)
- SAML decode output (if applicable)
- Manual findings from `fetch`, `execute-js`, `intercept`, and dual-session testing
- Shadow mode passive findings
- Secrets harvest results
- Journal entries
- **VPX export** for machine-readable assessment exchange

Rate each finding by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO) and include reproduction steps, evidence, and remediation recommendations. For findings with verify-workflow proofs, include the workflow definition and oracle evidence as definitive proof.
