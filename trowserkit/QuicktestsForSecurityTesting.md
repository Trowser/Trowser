# Security Quicktests — Manual Tester Guide

How to use Trowser's security quicktests for hands-on security testing. The quicktests automate the mechanical scanning work so you can focus on interpretation, manual exploration, and the creative attacks that scanners miss.

**Methodology and REST playbooks:** For phased testing, triage, proof patterns, and the full **playbook → drill-down** map, see **[SecurityTestingWithTrowser.md](SecurityTestingWithTrowser.md)**. Many quicktests mirror REST/MCP calls (`POST /api/security` = **1 Security Scan**, `POST /api/security/js-libraries` = **2 JavaScript Vulnerabilities**, etc.).

**Where to find them:** Script Console toolbar → **Quicktests** dropdown → **Security** folder.

**How to run:** Select a quicktest, click **Run** (or press Ctrl+Enter). Output appears in the Script Console. Assertions show PASS/FAIL with a summary at the end.

**Naming convention:** Menu entries are prefixed **1–4** (e.g. **1 Security Scan**, **2 Attack Surface From Network**) — the number is part of the quicktest name, not always the same as the methodology **Phase** section below. Run in order for systematic coverage, or run any quicktest independently.

---

## Phase 0 — Setup (manual)

No quicktests here — this is prep work you do before running any scans.

1. **Navigate to the target application** in Trowser.
2. **Enable Shadow** (Settings → Experimental → Shadow → On). Factory checks: XSS, Retire.js, Headers (REST: `POST /api/security/headers`), Network, Console (errors only), with GUI notifications; scope is same origin. WCAG, cookies, mixed content, source maps, and storage are off unless you enable them. Review findings via `GET /api/security/shadow` or the page-state shadow summary. Keep it enabled for the entire session.
3. **Enable Red Team Whisper** (Settings → Experimental → Red Team Whisper → On). After each navigation Trowser emits **clues** (hypotheses, not findings) from the page DOM and network. Stack and cache identification run **once per new domain**. The same clue is not toasted again during the session. Copy a toast for details to paste into notes or an LLM. Shadow already covers CSP, cookies, XSS, mixed content, source maps, storage, and Retire.js — Whisper will not repeat those. A comment or search box is **not** a chat-UI clue unless Whisper also sees a known chat-widget global or LLM-like network traffic (same matching as `llm-endpoint-discover`).
4. **(Optional) Start OOB callback detection** via the LLM or REST API: `POST /api/security/callbacks {"mode":"start"}`. This monitors for out-of-band interactions (blind XSS, DOM SSRF) throughout your session.
5. **(Optional) Start the journal** to track your findings: add notes, bugs, and observations via the REST API or let the LLM log them for you.

---

## Phase 1 — Reconnaissance

### Before running quicktests

Browse the application thoroughly — visit 5–10 key pages, submit a few forms, click through the main workflows. This populates the network log that the reconnaissance and scanning quicktests analyze.

### Quicktest: 2 Attack Surface From Network

**What it does:** Analyzes all captured network traffic to build an attack surface map — endpoints, HTTP methods, parameters (query, body, path), authentication patterns, and response structures. Same analysis as **`POST /api/security/attack-surface`** (MCP: `browser_attack_surface`).

**What to look for in the output:**
- Endpoints that accept user-controlled parameters (query strings, JSON bodies, path segments) — these are your injection targets for Phase 3.
- State-changing endpoints (POST/PUT/PATCH/DELETE) — candidates for CSRF and authorization testing.
- Endpoints with path parameters (e.g. `/api/user/{id}`) — IDOR candidates.
- Authentication patterns: which requests carry cookies, Bearer tokens, or CSRF headers?
- Any endpoints on unexpected hosts (API subdomains, third-party services).

**What you do next:** Use this map to plan which endpoints to test manually in Phase 3. Note down high-value targets: endpoints with sensitive data, admin-only operations, and anything that modifies server state.

---

## Phase 2 — Automated Scans

These quicktests run passive or low-impact analyses. They read the page DOM, check headers, scan JavaScript files, and inspect cookies/storage. Safe to run on any page.

**REST/MCP (no Script Console):** **`POST /api/security`** / **`browser_security`** — same module set as quicktest **1 Security Scan**. **`POST /api/security/js-libraries`** / **`browser_security_js_libraries`** — Retire.js only (**2 JavaScript Vulnerabilities**). See [SecurityTestingWithTrowser.md — Phase 2](SecurityTestingWithTrowser.md#phase-2--automated-scans) for `audit-all` vs overview and individual `/api/security/*` routes.

### Quicktest: 1 Security Scan

**What it does:** The broadest single passive security check — runs **11** audits on the current page (REST/MCP equivalent: **`POST /api/security`**):

| Section | What it catches |
|---------|----------------|
| Tech Stack Detection | Servers, frameworks, JS libraries, WAFs, CDNs. Reveals what you're attacking. |
| JavaScript Libraries (Retire.js) | Known CVEs in client-side libraries (jQuery, Angular, Bootstrap, etc.) |
| HTTP Security Headers | Missing/weak CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, server disclosure |
| CORS Configuration | Reflected origins, wildcard misconfiguration, null origin acceptance |
| DOM XSS Patterns | Inline event handlers, `javascript:` URLs, dangerous sinks (`eval`, `innerHTML`, `document.write`) |
| Mixed Content | HTTP resources loaded on HTTPS pages (scripts, images, iframes) |
| Cookie Security | Missing Secure/HttpOnly/SameSite flags, overly broad domains, excessive lifetimes |
| Source Maps & Debug | Accessible `.map` files (source code disclosure), framework debug mode |
| Web Storage | Auth tokens in localStorage/sessionStorage/**IndexedDB**, PII, stored XSS vectors |
| HTTP Methods | TRACE (XST risk), unrestricted PUT/DELETE on the document URL |
| Endpoint Discovery | Common admin/config paths (`/admin`, `/config`, `/swagger`, `.env`, etc.) |

**What to look for:** Any FAIL assertion. Pay special attention to:
- Missing CSP → the application has no defense against XSS execution.
- Missing HttpOnly on session cookies → XSS can steal sessions.
- Source maps accessible → full source code is public.
- Retire.js CVEs → check if the vulnerable code path is reachable.

**What you do next:** For each finding, decide whether it's exploitable in context. A missing CSP header is informational on a static marketing page but critical on a banking application. Cross-reference with findings from Phase 3.

### Quicktest: 2 JavaScript Vulnerabilities

**What it does:** Focused Retire.js CVE scan — the same Retire.js section as **1 Security Scan**, but standalone for quick re-checks (**REST/MCP:** **`POST /api/security/js-libraries`**). Useful after navigating to a different page that loads different JS bundles. Detection uses live-DOM fingerprints (including Bootstrap's jQuery plugin / `bootstrap.*` APIs), script URLs/filenames, and filecontent patterns inside fetched bundles. If the page loads few large bundled JS files, the result includes a caveat — a clean scan is not proof that nothing is hiding in the bundle.

**When to use:** Run this on each distinct page that loads different JavaScript (e.g., the login page vs. the dashboard vs. the admin panel).

### Quicktest: 2 SecretsHarvest

**What it does:** Unified credential/secret scan across six sources:

| Source | What it finds |
|--------|---------------|
| JS bundles | Hardcoded passwords, API keys, internal URLs, debug markers |
| Cookies & storage | JWT tokens, auth tokens, PII |
| Network responses | Leaked credentials, bearer tokens, password hashes in API responses |
| Network request headers | Bearer tokens, API keys in Authorization/X-Api-Key headers |
| Visible page text | Debug output, exposed secrets on the page |
| Source maps | Exposed `.map` files, framework debug mode indicators |

**What to look for:** CRITICAL findings (hardcoded credentials, leaked passwords in API responses) need immediate attention. HIGH findings (JWT tokens in localStorage, API keys in JS) are common but still risky.

**Prerequisites:** Browse the application first — the network response scan only checks traffic that has already been captured.

### Quicktest: 2 ThirdPartySecurity

**What it does:** Inventories all third-party resources (external scripts, stylesheets, iframes, fonts) and checks Subresource Integrity (SRI) coverage. Missing SRI on third-party scripts means a compromised CDN could inject malicious code.

**What to look for:**
- External scripts without `integrity` attributes — supply chain attack vector.
- Unexpected third-party domains — data exfiltration or tracking you didn't expect.
- Large transfer sizes from third parties — performance and trust implications.

### Quicktest: 2 JwtAnalysis

**What it does:** Finds JWT-shaped strings in cookies (including HttpOnly via the cookie jar), `localStorage`, and `sessionStorage`. Decodes header and payload, reports algorithm, expiry, and sensitive claim names (password, secret, api key paths, etc.).

**Prerequisites:** Navigate and authenticate if tokens only appear after login.

**What to look for:** `alg: none`, expired `exp`, sensitive claims in the payload, HS256/RS256 hygiene notes (algorithm confusion, weak secrets — follow up manually).

### Quicktest: 2 IndexedDbDump

**What it does:** Dumps IndexedDB for the current origin (CDP, with a JS fallback), then runs the same storage audit as **1 Security Scan** — now covering **localStorage, sessionStorage, and IndexedDB** for tokens, JWTs, and PII.

**Prerequisites:** Navigate first; log in if the app only writes IndexedDB after auth.

**What to look for:** Auth tokens or JWTs in IndexedDB, unexpected databases, PII in store values.

### Quicktest: 3 Dom Flows

**What it does:** Builds a DOM XSS **flow graph** from the runtime sensor: attacker-controlled source → sink (`innerHTML`, `eval`, `location`, script insertion, …) → consequence (`exec`, `nav-hijack`, inert). Default is observe-only. Fails the assertion only on **executable** (`exec`) chains.

**Prerequisites:** Browse the page so the sensor sees real source reads. For planted canaries, switch the script to `PrintDomFlowsReport("probe")` (and REST/MCP `safetyMode: active` when you want URL/hash canaries).

**What to look for:** `exec` and `nav-hijack` rows. Temporal correlations without value-match are weaker — treat them as leads.

### Quicktest: 2 ClientSurface

**What it does:** Maps the current page (same as `POST /api/security/client-surface`) and prints a triage checklist for browser-side bug classes: XS-Leaks, DOM XSS, client-side CSRF, postMessage, client prototype pollution, DOM clobbering, DOM open redirect, client-side authorization, HTML injection, CSTI, web storage, frontend business logic, reverse tabnabbing, XSSI, service workers, clickjacking, CORS, CSS injection, dangling markup, Trusted Types, and WebSocket. Each row is **pursue**, **lead**, **manual**, **not-observed**, or **dismiss**. It does not run those scanners. **Dismiss** means the class is absent on collected evidence; **not-observed** means coverage was incomplete (do not treat as skipped).

**Prerequisites:** Browse the app first, ideally with Shadow runtime on, so the sensor has seen real sinks and listeners. The script may reload the page once to install the sensor.

**What to look for:** **Pursue** rows are the ones to run next (the `next:` line names the tool). **Dismiss** means skip that class on this page. **Manual** rows (authorization in the UI, business logic) are never cleared by this quicktest. An empty runtime log leaves sink-based classes as leads — that is not a clean bill of health.

**What you do next:** Run the follow-up named on each pursue or lead row (DOM XSS audit, postMessage, gadget chains, CSTI, storage audit, XS-Leaks). Ignore dismiss rows until you open a different route.

### Quicktest: 3 Xssi Scan

**What it does:** Same as `POST /api/security/xssi-scan` / MCP `browser_security_xssi_scan`. Re-GETs script/JSON URLs from the network log (with session cookies) and flags JSONP/callback wrappers, JavaScript array bodies, global assignments, and JSON arrays missing `nosniff`. Hygiene-tier leads only — not a cross-origin script-include proof.

**Prerequisites:** Browse authenticated flows first so API/JSONP responses are in the network log (response bodies help client-surface triage; the scan re-fetches either way).

**What to look for:** `[high]` JSONP / script-includable endpoint rows. Empty result after a lead on **2 Client Surface** usually means URLs were not re-captured — pass explicit `urls[]` or browse the sensitive endpoint again.

### Quicktest: 2 FramesAndOrigins

**What it does:** Lists every iframe (including nested and cross-origin) with `origin`, `sameOrigin`, `inspectable`, and `outOfScope`. Cross-origin frames with a WebView2 handle are inspectable via `ExecuteJsInFrame`.

**When to use:** Pages with ads, SSO, payment widgets, or sandboxed embeds.

### Quicktest: 3 XsLeaks

**What it does:** Runs the XS-Leaks scanner with **`autoStates: true`** first (identity pairs, search hit/miss from session traffic, or protected URL vs synthetic miss). Falls back to **current URL vs synthetic 404** when auto-derivation fails (informational tier when distinguishable). Prints verdicts, tier (`exploitable` / `hygiene` / `informational`), and probe `mitigatedBy` headers.

**Prerequisites:** Not available in `--safe` (mocks). Browse authenticated APIs or search endpoints on the target host before running so autoStates can build secret-dependent pairs.

**What to look for:** **`exploitable`** tier with `distinguishable` and no effective isolation (see `mitigationReason`). Ignore informational hits from existence-only pairs unless you are auditing public resource enumeration. Re-run with `safetyMode: active` for timing/popup techniques.

### Quicktest: 3 OidcFromNetwork

**What it does:** Reads the OIDC login the browser actually saw, then (when an issuer is known) fetches the discovery document and runs provider checks. Session posture covers a normal `/authorize` redirect, a bearer token, and a reverse-proxy / BFF login (session cookie such as `oidcproxy.cookie`, a hop to the login UI, OIDC claims on an app API, no authorize request). Claim values are not printed. Provider checks cover grant types, PKCE, scopes, signing algorithms, and endpoint reachability. Live grant-type probes stay off (`testGrantTypes: false`).

**Pass an issuer yourself** when auto-detect finds nothing. That is normal for a BFF: the issuer is not the login UI host. At the top of the script set `string? issuer = "https://login.example.com/realms/myrealm";` and run again. The same string is the `issuer` field on `POST /api/security/oidc-analyze`.

**Prerequisites:** Browse the app or complete an OIDC login so the network log contains the login.

**What to look for:** Session cookie flags, national-identifier claim types exposed to the page, tokens left in URLs. On the provider audit: implicit or ROPC grants, `plain` PKCE, HTTP endpoints, weak signing algorithms, open dynamic registration. Missing discovery is normal — read **`dossier`** and **`rpTokenFindings`**.

### Quicktest: 4 OAuthFlowFromNetwork

**What it does:** Passive **`oauth-flow-test`** from the network log: state, PKCE, fragment leaks, mix-up hints, plus **`dossier`**. Use after a front-channel login (not BFF-only).

**Prerequisites:** Browse through OAuth login so `/authorize` and callback appear in the network log.

**What to look for:** Missing state, PKCE stripped, tokens in fragment, weak state. Active redirect_uri and code-replay probes need API `safetyMode: active`.

### Quicktest: 2 JsAudit

**What it does:** Downloads external `script[src]` files from the current DOM and scans raw script text for credential-like assignments, internal/private URLs, and debug/test markers. Complements **2 SecretsHarvest** (which also pulls JS via the harvest pipeline) with a focused Retire-free static pass.

**Prerequisites:** A page that references external bundles; uses server-side `HttpClient` fetches — only run on targets you are allowed to test.

---

## Phase 3 — Active Testing

These quicktests send real requests to the server. They test for actual vulnerabilities by probing endpoints with payloads. The findings here are higher-confidence than Phase 2 because they measure server behavior, not just static page properties.

### Quicktest: 3 Swaggering

**What it does:** **Swaggering** — not Postman, but something Postman cannot do out of the box: discover OpenAPI/Swagger, then hit **every documented operation** using your **logged-in browser session** (cookie jar). Runs inventory (documented vs shadow APIs), spec cost hints, smoke/error/auth/slow probes, shadow path checks, and auto-scan on the merged surface. Default **thorough** depth (~20 minutes on large specs).

**Prerequisites:** Log in on staging (authorized testing only). Open Swagger UI or ensure `/openapi.json` (or similar) is reachable. Optional: browse a few pages so CSRF/API headers can be replayed from traffic.

**What to look for:** `swaggering-server-error`, `swaggering-verbose-error`, `swaggering-auth-anomaly`, `swaggering-shadow-exposed`, spec `costly-*` hints, plus auto-scan injection hits. Treat green as “contract smoke passed”, not “fully pentested”.

**Toggles:** Edit `depth` and `safetyMode` at the top of the script (`passive` for spec-only, `safe` for GET-only).

### Quicktest: 3 AutoScan

**What it does:** Discovers endpoints from captured network traffic, then automatically runs five targeted scanners:

| Scanner | What it tests | Endpoint selection |
|---------|--------------|-------------------|
| SQL Injection | Error-based, union-based, blind boolean/timing SQLi | Endpoints with query/body parameters |
| IDOR | Access control on path parameters (e.g. `/api/user/{id}`) | Endpoints with path segments |
| CSRF | Missing/invalid anti-CSRF tokens on state-changing requests | POST/PUT/PATCH/DELETE endpoints |
| Path Traversal | `../../etc/passwd` style payloads in query parameters | GET endpoints with path-like params |
| Mass Assignment | Injecting privileged fields (`role`, `isAdmin`) into JSON bodies | JSON POST/PUT/PATCH endpoints |

**Prerequisites:** Browse the application thoroughly first. The scanner only tests endpoints it has seen in the network log.

**What to look for:** Any finding rated MEDIUM or above. The assertion fails on MEDIUM+ severity by default.

### Quicktest: 3 CacheProbe

**What it does:** Cache testing in the order that matters: **identify** (headers / tech-stack via cache-map) → **miss-forcing header** on the clean URL → **error store** → **fully clean GET**. Query-string busters are used only in the map step. If a bypass header is found, optionally runs unkeyed-header canary poison on the live key. If session cookies exist, runs cache deception on the current path.

**Prerequisites:** Navigate to the target (logged-in session recommended for map/deception). Pollution and poison send real requests; a confirmed pollution finding stores an error other users may receive.

**What to look for:** `cache-error-stored`, `cached-persistence`, cache deception on authed paths. “A cache exists” is not a vulnerability.

### Quicktest: 3 FirewallTest

**What it does:** **Active** checks that CSP, Subresource Integrity, iframe `sandbox`, and Permissions-Policy actually block realistic bypass attempts in the live WebView (injections, eval probes, etc.). This is enforcement testing, not header parsing alone.

**What to look for:** Any defense reported as **bypassed** — treat as high priority on pages that should resist XSS or supply-chain script tampering.

### Quicktest: 3 GraphqlAnalysis

**What it does:** Auto-detects a GraphQL HTTP endpoint from the network log (or uses the current capture context), then runs the nine GraphQL security probes (introspection, batching, alias amplification, depth/limits, field suggestions, draft access, rate-limit headers, etc.). Sends real GraphQL payloads to the server.

**Prerequisites:** Browse the app so a GraphQL POST is captured, or ensure the target exposes a standard GraphQL URL pattern. Authenticate first if introspection requires auth.

**What to look for:** Open introspection on production, unlimited query depth, batching that bypasses rate limits, sensitive types in the schema.

### Quicktest: TotalLogoutTest

**What it does:** Semi-manual check that logout actually ends the session. While you are on an authenticated-only URL it captures cookies, `localStorage`, `sessionStorage`, and IndexedDB, pauses **15 seconds** so you can log out in the browser, then re-applies that client state and opens the original URL. **FAIL** if the same URL (origin + path) is still loaded; **PASS** if the browser was sent somewhere else. Complements `logout-invalidation-probe` (which needs a detectable logout URL) — this one works when logout is a SPA button, SSO, or otherwise hard to automate.

**Prerequisites:** Log in and stay on a page that requires authentication (not the login screen). Be ready to click logout during the pause. Increase `logoutPauseSeconds` at the top of the script if 15 seconds is tight.

**What to look for:**
- **FAIL** — after replay, the **same URL** (origin + path) is still loaded. Logout did not invalidate the session.
- **PASS** — the browser was redirected away (login, timeout, public page, …). HTTP status is ignored.
- After the script: **"Now you try to login, if you don't have to provide credentials, the logout isn't total."** Silent SSO / remember-me / IdP session is a second failure mode the replay step cannot see.

**What you do next — the manual work that matters most:**

The quicktests cover the automated scanning, but the highest-impact security testing requires human judgment. Here's what to do after running the automated scans:

#### Authentication testing (manual)
- **Brute-force / lockout:** Try 10–15 wrong passwords. Does the account lock? Is there a CAPTCHA? Use the LLM or REST API `POST /api/security/brute-force` for systematic testing.
- **Credential stuffing:** Try common passwords (`password`, `123456`, `admin`) on known usernames.
- **Session fixation:** Can you set a session cookie before login and have the server accept it after login?
- **Total logout:** Run **TotalLogoutTest** on an authenticated page, log out during the pause, then follow the handover — if login does not ask for credentials, SSO/remember-me survived.

#### Authorization testing (manual)
- **Vertical privilege escalation:** Log in as a regular user and try to access admin endpoints found in Phase 1.
- **Horizontal IDOR:** Take an object ID from your account and try accessing another user's object. Use the attack surface map to find ID-bearing endpoints.
- **Missing function-level access control:** Can an unauthenticated user call authenticated API endpoints directly?

**Dual-session testing (if you have two Trowser instances):**
- Log in as admin in Trowser A, as attacker in Trowser B.
- Register B as a peer: `POST /api/peer/register {"name":"attacker","baseUrl":"http://localhost:6924"}`.
- Run `POST /api/authz/diff` to compare what each identity can see.
- Run `POST /api/authz/boundary` to test if the attacker can access the admin's resources.

**Auth Control Identifier (which cookies/headers are actually enforced):**
- Browse and trigger the API call(s) of interest.
- Open **Script Console → Endpoints**, select the request(s), check **Auth Control Identifier**, Safety **Active**, then **Run**.
- Review the results table for `ignored` (sent but never validated — e.g. decorative CSRF tokens) and `presence-only` (existence check without content check). `enforced` means omit and one-character tamper both change the response.
- Also available from the HTTP Request Editor (**Identify auth controls…**).

#### Injection testing (manual)
- **Stored XSS:** Submit XSS payloads through forms, then navigate to where they render (possibly a different page or user role). Use `POST /api/security/trace-input` to trace the payload through the full pipeline.
- **SQL injection (targeted):** Use `POST /api/security/sqli-scan` on specific login or search endpoints with marker-based templates.
- **SSTI / template injection:** Try `{{7*7}}` and `${7*7}` in text inputs.

#### Business logic testing (manual)
- Price tampering (modify amounts in API requests).
- Negative quantities, zero-value transactions.
- Race conditions: use `POST /api/fetch/batch {"concurrent":true}` to send parallel requests (e.g., redeem a coupon twice).
- Pagination abuse: request `limit=999999` or `offset=-1`.

---

## Phase 4 — SAML / Federation

Only relevant if the target application uses SAML-based SSO.

### Quicktest: 3 Saml From Network

**What it does:** Finds the latest SAMLRequest or SAMLResponse in the captured network traffic, decodes it (handles both HTTP-Redirect and HTTP-POST bindings), and performs security analysis.

**Prerequisites:** Complete an SSO login flow before running this quicktest. The SAML messages must be in the network log.

**What to look for:**
- Missing XML signatures → assertion forgery is possible (CVE-2025-47949).
- Weak signing algorithms (SHA-1) → signature could be forged.
- Missing audience restriction → cross-SP replay attacks.
- Expired assertions accepted → replay window is open.
- NameID format and attributes → verify the correct identity is asserted.

**What you do next — manual SAML testing:**

These attacks require the REST API or LLM assistance (no quicktest yet):

1. **SAML replay:** Capture an assertion with `POST /api/security/saml-capture {"mode":"next-login"}`, then replay it with modifications via `POST /api/security/saml-replay`:
   - Plain replay (reuse the same assertion).
   - Signature stripping (`removeSignature: true`).
   - Identity spoofing (`changeSubject: "admin@example.com"`).
   - Cross-SP replay (`removeAudienceRestriction: true`).
   - Expired assertion (`expireAssertion: true`).
2. **LOA enforcement:** Authenticate with the weakest method, then SSO to sensitive service providers. If it works, LOA isn't enforced.
3. **SLO propagation:** Log out from one SP, then check if other SPs still have active sessions.
4. **Orphaned sessions:** Start a login flow, skip consuming the identity response, then test if SLO can clean up that session.

---

## Phase 5 — Advanced Testing

Most items here are still manual or LLM-driven. **3 HttpSmuggling** is available as a quicktest for the current document URL.

### Quicktest: 3 HttpSmuggling

**What it does:** One origin-level raw TCP scan (CL-TE, TE-CL, TE-TE, CL-CL, TE obfuscation). **Act only on `verdict: confirmed`** — a repeated canary 404 from a PortSwigger CL.TE/TE.CL prefix. Timing stalls, duplicate Content-Length, and HEADER hygiene are printed as notes, not failures.

**What to look for:** `verdict: confirmed` + `confirmationMethod: differential-response`. Hand that raw HTTP to infrastructure. Do not file TE obfuscation acceptance or Cloudflare-class duplicate-CL 200s as smuggling.

### MITM simulation
Set request breakpoints with `POST /api/intercept`, trigger a request, then fulfill it with a tampered response via `POST /api/intercept/fulfill`. Verify whether the frontend blindly trusts the modified data.

### Fault injection
Use the **Reliability → FaultInjection** quicktest, or run `POST /api/interrupter` via the REST API. Tests how the application handles server errors (500), empty responses, invalid JSON, slow responses, and corrupted data.

### Race conditions
Send concurrent requests with `POST /api/fetch/batch {"concurrent":true}` or `POST /api/load-test`. Look for: duplicate resource creation, mixed status codes, state corruption.

**Race Lab (recommended for TOCTOU / multi-session):** Register a peer (`POST /api/peer/register`) when you need a second browser identity. GUI **More options → Race Lab…** or `POST /api/race-lab/run` with explicit `requests[]` (`session`: **`all-peers`** \| `driver` \| peer name; `role`: **`observe`** for read/idempotent traffic, **`mutate`** for single-use POSTs, **`check`** for TOCTOU validation). Built-in presets **Hammer / Spike / Sequential / Random** set timing only. Copy-paste REST examples: [trowser-api-reference.md § Race Lab](trowser-api-reference.md#race-lab-multi-session-race--toctou). Script: `Resources/Quicktests/Security/RaceLab.csx` (`RunRaceLabAsync`). Traffic discovery quick scan: `POST /api/security/race-condition-scan`.

### HTTP request smuggling (REST variant)
The same engine backs **3 HttpSmuggling** and `POST /api/security/smuggling` with `safetyMode: "active"`. Use the REST API when you need custom URLs, techniques, or timeouts from automation outside the Script Console. Confirmed = differential 404; everything else is informational.

### Content-Type confusion
Send unexpected Content-Types (`application/xml`, `text/xml`, `multipart/mixed`) to API endpoints via `POST /api/fetch`. Many servers return 500 with parser info instead of 415.

---

## Phase 6 — Verification & Reporting (manual)

See also **[SecurityTestingWithTrowser.md — Report Compilation](SecurityTestingWithTrowser.md#report-compilation)** for the full source list (chains, VPX, journal, shadow).

1. **Review Shadow findings:** If you enabled it in Phase 0, check `GET /api/security/shadow` for passively detected issues accumulated across all pages you visited.
2. **Check OOB callbacks:** If you enabled callback detection, check `GET /api/security/callbacks` for out-of-band interactions.
3. **Verify exploitability:** For each finding, confirm it's exploitable — not just a scanner flag. Use `POST /api/security/verify` to prove XSS execution with automated inject-navigate-check flows.
4. **Export the journal:** `GET /api/journal/export?format=markdown` produces a structured report with all bugs, observations, and test notes from the session.
5. **Rate findings by severity:** CRITICAL (RCE, auth bypass, data breach), HIGH (XSS, SQLi, IDOR), MEDIUM (missing headers, weak cookies), LOW (info disclosure, debug mode), INFO (observations).

---

## Quicktest Summary

| # | Quicktest (menu name) | Methodology phase | REST/MCP (when applicable) | Prerequisites |
|---|------------------------|-------------------|----------------------------|---------------|
| 1 | Security Scan | Automated Scans | `POST /api/security` · `browser_security` | Navigate to target page |
| 2 | Attack Surface From Network | Reconnaissance | `POST /api/security/attack-surface` | Browse the app first |
| 2 | JavaScript Vulnerabilities | Automated Scans | `POST /api/security/js-libraries` | Navigate to target page |
| 2 | Secrets Harvest | Automated Scans | `POST /api/security/secrets-harvest` | Browse the app first |
| 2 | Third Party Security | Automated Scans | `POST /api/third-party` | Navigate to target page |
| 2 | Jwt Analysis | Automated Scans | `POST /api/security/jwt-analyze` (`safetyMode: active`) | Log in first if needed |
| 2 | Indexed Db Dump | Automated Scans | (scripting / storage helpers) | Log in first if needed |
| 2 | Client Surface | Automated Scans | `POST /api/security/client-surface` | Browse first; Shadow runtime helps |
| 2 | Frames And Origins | Automated Scans | — | Page with embeds |
| 2 | Js Audit | Automated Scans | `POST /api/security/js-audit` (`safetyMode: active`) | Navigate to target page |
| 3 | Dom Flows | Automated Scans | `POST /api/security/dom-flows` | Navigate; interact with the page |
| 3 | Xssi Scan | Automated Scans | `POST /api/security/xssi-scan` | Browse APIs/JSONP first |
| 3 | Oidc From Network | Automated Scans | `POST /api/security/oidc-analyze` | Browse / OIDC login first |
| 3 | Costly Operations | Automated Scans | `POST /api/security/costly-operations` | Browse the app first |
| 3 | Auto Scan | Active Testing | `POST /api/security/auto-scan` (`safetyMode: active`) | Browse the app first |
| 3 | Cache Probe | Active Testing | cache-map / pollution / poison APIs | Navigate to target page |
| 3 | Firewall Test | Active Testing | `POST /api/security/firewall-test` | Navigate to target page |
| 3 | Graphql Analysis | Active Testing | `POST /api/security/graphql-analyze` | GraphQL traffic or public endpoint |
| 3 | Http Smuggling | Advanced | `POST /api/security/smuggling` | Navigate to target origin |
| 3 | Xs Leaks | Active Testing | `POST /api/security/xs-leaks` | Not `--safe`; browse for autoStates |
| 3 | Saml From Network | SAML / Federation (Phase 4) | `POST /api/security/saml-decode` | Complete an SSO flow |
| 4 | Total Logout Test | Active Testing | `logout-invalidation-probe` (when URL known) | Authenticated-only URL |
| 4 | OAuth Flow From Network | Federation | `POST /api/security/oauth-flow-test` | OAuth login in network log |

---

## Trowser Twelve (orchestrated category playbooks)

**Where to find them:** Script Console → **Quicktests** → **Security** → **Trowser Twelve**.

These are separate from the numbered Phase 1–5 quicktests above. Each runs one **security playbook** — a curated chain of scanners for a single vulnerability category aligned with the Trowser Twelve taxonomy. Output is a colorized markdown report with severities, step metrics, and suggested `nextActions`.

**Twelve playbooks, `Axx` IDs:** The group runs **12 category playbooks** (`A01`–`A07`, `A09`, `A11`–`A14`). Labels go up to **A14** for extensions (SSRF, availability, LLM, other). **A08** (software/data integrity) has no standalone playbook — use **A03 Supply Chain**. **A10** is unused; SSRF is **A11**. See **[SecurityTestingWithTrowser.md — Playbook → drill-down map](SecurityTestingWithTrowser.md#playbook--drill-down-map)** for what to run after each playbook (authz, XSS, SSRF, reporting, etc.).

**Not in the Trowser Twelve menu:** `quick` (Quick LLM sweep), `a05a-injection-core`, `a05b-injection-templates`, and `a05c-injection-advanced` are **REST/MCP orchestration only** — `POST /api/orchestrate/{id}` / `browser_orchestrate_run`.

**Prerequisites:**
1. Navigate to the target and browse key flows first (network log must be populated).

**Safety:** All Trowser Twelve quicktests default to `safetyMode: "safe"` — passive/read-only checks plus safe probes only. Edit the script and set `safetyMode: "active"` when you need live injection, fuzz, or fault-injection steps inside a playbook.

| Quicktest (menu) | Playbook ID | What it covers | Drill-down (methodology) |
|------------------|-------------|----------------|---------------------------|
| A00 Full Site Security | `full` | All categories in sequence + attack-chain correlation | [SecurityTestingWithTrowser.md](SecurityTestingWithTrowser.md#playbook--drill-down-map) → chains, proof, Phase 7 |
| A00 Specific Scan | *(uses `full` engine)* | Active **`depth: quick`** on one URL/method from the network log (no crawl) | Targeted re-run after browsing the API call |
| A01 Access Control | `a01-access` | IDOR, authz, horizontal/vertical privilege | authz/*, BAC, IDOR sections |
| A02 Misconfiguration | `a02-misconfig` | Headers, CORS, cookies, discovery, methods | Phase 2 scans; discover SPA gotchas |
| A03 Supply Chain | `a03-supplychain` | Retire.js, manifests, CI/CD, bundle fingerprinting | Secrets harvest; `supply-chain-scan` |
| A04 Crypto and Secrets | `a04-crypto` | JWT hygiene, secrets harvest, session entropy, storage | Secrets methodology; IndexedDB dump quicktest |
| A05 Injection | `a05-injection` | SQLi, XSS, SSTI, CSTI, parser confusion, DOM XSS flow graph (full) | XSS Testing; client-source-led investigation |
| A06 Insecure Design | `a06-design` | Race conditions, business-logic indicators | Phase 3 & 6 business logic |
| A07 Authentication | `a07-authn` | Login flows, session handling, brute-force signals | Brute-force / lockout; Total Logout Test |
| A09 Operational Security | `a09-opsec` | Logging leaks, fail-open, debug exposure | Forced-error triage |
| A11 SSRF | `a11-ssrf` | Server-side request forgery probes | SSRF custom payloads |
| A12 Availability | `a12-availability` | Rate limits, body-size, ReDoS + passive costly-operations | `costly-operations` API |
| A13 AI and LLM | `a13-llm` | Application-layer OWASP LLM Top 10 | A13 / `llm-redteam-scan` in methodology guide |
| A14 Other | `a14-other` | Smuggling, host-header, cache chain, open redirect, XS-Leaks | Phase 6 advanced |
| *(REST/MCP only)* | `quick` | ~60–120s LLM sweep (attack-surface + misconfig + access + injection slice) | `POST /api/orchestrate/quick` |
| *(REST/MCP only)* | `a05a` / `a05b` / `a05c` | Injection slices for short agent budgets | See SecurityTestingWithTrowser playbook map |

**Start here:** Run **A00 Full Site Security** for a one-call assessment, then drill into individual categories for depth.

**Findings across playbooks:** Cross-playbook deduplication keeps unique findings in the live session — you do **not** need to copy each Script Console report before running the next playbook. Later playbooks suppress already-seen issues and print a warning. When you want a durable snapshot (checkpoint mid-session, or final package after A01–A14), use **Settings → Experimental… → VPX Export…** to save the merged VPX 1.1 document. **VPX Import…** restores a saved file into the session so later playbooks continue to deduplicate against it. Same document as `GET /api/vpx/export` / `browser_vpx_export`.

**REST/MCP:** Same playbooks via `POST /api/orchestrate/{id}` or MCP orchestration tools. Dry-run the step plan with `POST /api/orchestrate/dry-run/{id}` before switching to `active` mode.

---

## What the Quicktests Don't Cover (and Why)

Some security APIs **still** don't have quicktests because they need custom templates, multi-step flows, or parameters. Use the REST API, MCP tools, or the Trowser LLM:

| API | Why no quicktest | How to use it |
|-----|-----------------|---------------|
| SQLi Scan (`security/sqli-scan`) | Needs a specific request template with injection markers | REST/MCP with request template |
| IDOR Scan (`security/idor-scan`) | Needs a URL template with ID markers | REST/MCP with request template |
| Brute Force (`security/brute-force`) | Needs login URL and body template | REST/MCP with login endpoint config |
| Trace Input (`security/trace-input`) | Needs CSS selectors for input + submit elements | REST/MCP with element selectors |
| SAML Replay (`security/saml-replay`) | Interactive: capture, modify, replay — multiple steps | REST/MCP with captured assertion |
| CORS probing (deep) | Document-only CORS is in **1 Security Scan** / `POST /api/security`; multi-endpoint sweep needs flags | `POST /api/security/cors` with `includeAttackSurfaceUrls: true` or re-run overview |
| Page passive rollup | Same modules as **1 Security Scan** | `POST /api/security` / `browser_security` |
| Retire.js only | Same as **2 JavaScript Vulnerabilities** | `POST /api/security/js-libraries` |

**Tip:** Many of these are easier to use by asking the Trowser LLM in the chat. Say "test this login for SQL injection" and it will call the right APIs with the right parameters.
