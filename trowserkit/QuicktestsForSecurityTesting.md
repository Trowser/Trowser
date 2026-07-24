# Security Quicktests — Manual Tester Guide

How to use Trowser's security quicktests for hands-on security testing. The quicktests automate the mechanical scanning work so you can focus on interpretation, manual exploration, and the creative attacks that scanners miss.

**Where to find them:** Script Console toolbar → **Quicktests** dropdown → **Security** folder.

**How to run:** Select a quicktest, click **Run** (or press Ctrl+Enter). Output appears in the Script Console. Assertions show PASS/FAIL with a summary at the end.

**Naming convention:** Each quicktest is prefixed with a phase number (1–4) matching the testing methodology below. Run them in order for systematic coverage — but any quicktest can be run independently at any time.

---

## Phase 0 — Setup (manual)

No quicktests here — this is prep work you do before running any scans.

1. **Navigate to the target application** in Trowser.
2. **Enable Security Shadow** (Settings → Shadows → Security Shadow → On). This runs passive security checks on every page you visit and accumulates findings in the background. You can review them at any time via `GET /api/security/shadow` or by checking the shadow summary in the page state. Keep it enabled for the entire session.
3. **Enable Red Team Whisper** (Settings → Shadows → Red Team Whisper → On). After each navigation, Trowser generates contextual attack hints based on the page's DOM and network patterns. Useful for spotting things you might not think to test.
4. **(Optional) Start OOB callback detection** via the LLM or REST API: `POST /api/security/callbacks {"mode":"start"}`. This monitors for out-of-band interactions (blind XSS, DOM SSRF) throughout your session.
5. **(Optional) Start the journal** to track your findings: add notes, bugs, and observations via the REST API or let the LLM log them for you.

---

## Phase 1 — Reconnaissance

### Before running quicktests

Browse the application thoroughly — visit 5–10 key pages, submit a few forms, click through the main workflows. This populates the network log that the reconnaissance and scanning quicktests analyze.

### Quicktest: 1 AttackSurfaceFromNetwork

**What it does:** Analyzes all captured network traffic to build an attack surface map — endpoints, HTTP methods, parameters (query, body, path), authentication patterns, and response structures.

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

### Quicktest: 2 SecurityScan

**What it does:** The broadest single security check — runs 10 distinct audits on the current page:

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
| Web Storage | Auth tokens in localStorage (should be in cookies), PII, stored XSS vectors |
| HTTP Methods | TRACE (XST risk), unrestricted PUT/DELETE on the document URL |
| Endpoint Discovery | Common admin/config paths (`/admin`, `/config`, `/swagger`, `.env`, etc.) |

**What to look for:** Any FAIL assertion. Pay special attention to:
- Missing CSP → the application has no defense against XSS execution.
- Missing HttpOnly on session cookies → XSS can steal sessions.
- Source maps accessible → full source code is public.
- Retire.js CVEs → check if the vulnerable code path is reachable.

**What you do next:** For each finding, decide whether it's exploitable in context. A missing CSP header is informational on a static marketing page but critical on a banking application. Cross-reference with findings from Phase 3.

### Quicktest: 2 JavaScriptVulnerabilities

**What it does:** Focused Retire.js CVE scan — the same check that's in SecurityScan, but standalone for quick re-checks. Useful after navigating to a different page that loads different JS bundles.

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

### Quicktest: 2 OidcFromNetwork

**What it does:** Same conceptual workflow as **4 SamlFromNetwork**, but for **OpenID Connect**. Auto-detects the issuer from captured traffic (e.g. `.well-known/openid-configuration` requests, Bearer JWT `iss`, `/authorize` URLs), fetches the discovery document, and runs provider checks (grant types, PKCE, scopes, signing algorithms, endpoint reachability, optional dynamic client registration probe). Does **not** run live grant-type abuse tests by default (`testGrantTypes: false` in the quicktest).

**Prerequisites:** Browse the app or complete an OIDC login so the network log contains IdP traffic.

**What to look for:** Implicit or ROPC grants, `plain` PKCE, HTTP (non-TLS) endpoints, weak signing algorithms, open dynamic registration, admin/financial scopes exposed.

### Quicktest: 2 JsAudit

**What it does:** Downloads external `script[src]` files from the current DOM and scans raw script text for credential-like assignments, internal/private URLs, and debug/test markers. Complements **2 SecretsHarvest** (which also pulls JS via the harvest pipeline) with a focused Retire-free static pass.

**Prerequisites:** A page that references external bundles; uses server-side `HttpClient` fetches — only run on targets you are allowed to test.

---

## Phase 3 — Active Testing

These quicktests send real requests to the server. They test for actual vulnerabilities by probing endpoints with payloads. The findings here are higher-confidence than Phase 2 because they measure server behavior, not just static page properties.

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

### Quicktest: 3 FirewallTest

**What it does:** **Active** checks that CSP, Subresource Integrity, iframe `sandbox`, and Permissions-Policy actually block realistic bypass attempts in the live WebView (injections, eval probes, etc.). This is enforcement testing, not header parsing alone.

**What to look for:** Any defense reported as **bypassed** — treat as high priority on pages that should resist XSS or supply-chain script tampering.

### Quicktest: 3 GraphqlAnalysis

**What it does:** Auto-detects a GraphQL HTTP endpoint from the network log (or uses the current capture context), then runs the nine GraphQL security probes (introspection, batching, alias amplification, depth/limits, field suggestions, draft access, rate-limit headers, etc.). Sends real GraphQL payloads to the server.

**Prerequisites:** Browse the app so a GraphQL POST is captured, or ensure the target exposes a standard GraphQL URL pattern. Authenticate first if introspection requires auth.

**What to look for:** Open introspection on production, unlimited query depth, batching that bypasses rate limits, sensitive types in the schema.

**What you do next — the manual work that matters most:**

The quicktests cover the automated scanning, but the highest-impact security testing requires human judgment. Here's what to do after running the automated scans:

#### Authentication testing (manual)
- **Brute-force / lockout:** Try 10–15 wrong passwords. Does the account lock? Is there a CAPTCHA? Use the LLM or REST API `POST /api/security/brute-force` for systematic testing.
- **Credential stuffing:** Try common passwords (`password`, `123456`, `admin`) on known usernames.
- **Session fixation:** Can you set a session cookie before login and have the server accept it after login?

#### Authorization testing (manual)
- **Vertical privilege escalation:** Log in as a regular user and try to access admin endpoints found in Phase 1.
- **Horizontal IDOR:** Take an object ID from your account and try accessing another user's object. Use the attack surface map to find ID-bearing endpoints.
- **Missing function-level access control:** Can an unauthenticated user call authenticated API endpoints directly?

**Dual-session testing (if you have two Trowser instances):**
- Log in as admin in Trowser A, as attacker in Trowser B.
- Register B as a peer: `POST /api/peer/register {"name":"attacker","baseUrl":"http://localhost:6924"}`.
- Run `POST /api/authz/diff` to compare what each identity can see.
- Run `POST /api/authz/boundary` to test if the attacker can access the admin's resources.

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

### Quicktest: 4 SamlFromNetwork

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

Most items here are still manual or LLM-driven. **5 HttpSmuggling** is available as a quicktest for the current document URL.

### Quicktest: 5 HttpSmuggling

**What it does:** Opens raw TCP connections to the host of the current page and runs **timing-based** CL-TE, TE-CL, TE-TE, CL-CL, and Transfer-Encoding obfuscation probes. It does not complete a smuggled request; it looks for timing differentials consistent with desynchronized framing.

**What to look for:** HIGH or MEDIUM findings — triage with infrastructure team; confirm with manual testing or dedicated smuggling tooling if needed.

### MITM simulation
Set request breakpoints with `POST /api/intercept`, trigger a request, then fulfill it with a tampered response via `POST /api/intercept/fulfill`. Verify whether the frontend blindly trusts the modified data.

### Fault injection
Use the **Reliability → FaultInjection** quicktest, or run `POST /api/interrupter` via the REST API. Tests how the application handles server errors (500), empty responses, invalid JSON, slow responses, and corrupted data.

### Race conditions
Send concurrent requests with `POST /api/fetch/batch {"concurrent":true}` or `POST /api/load-test`. Look for: duplicate resource creation, mixed status codes, state corruption.

### HTTP request smuggling (REST variant)
The same engine backs **5 HttpSmuggling** and `POST /api/security/smuggling` with `safetyMode: "active"`. Use the REST API when you need custom URLs, techniques, or timeouts from automation outside the Script Console.

### Content-Type confusion
Send unexpected Content-Types (`application/xml`, `text/xml`, `multipart/mixed`) to API endpoints via `POST /api/fetch`. Many servers return 500 with parser info instead of 415.

---

## Phase 6 — Verification & Reporting (manual)

1. **Review Security Shadow findings:** If you enabled it in Phase 0, check `GET /api/security/shadow` for passively detected issues accumulated across all pages you visited.
2. **Check OOB callbacks:** If you enabled callback detection, check `GET /api/security/callbacks` for out-of-band interactions.
3. **Verify exploitability:** For each finding, confirm it's exploitable — not just a scanner flag. Use `POST /api/security/verify` to prove XSS execution with automated inject-navigate-check flows.
4. **Export the journal:** `GET /api/journal/export?format=markdown` produces a structured report with all bugs, observations, and test notes from the session.
5. **Rate findings by severity:** CRITICAL (RCE, auth bypass, data breach), HIGH (XSS, SQLi, IDOR), MEDIUM (missing headers, weak cookies), LOW (info disclosure, debug mode), INFO (observations).

---

## Quicktest Summary

| # | Quicktest | Phase | What it does | Prerequisites |
|---|-----------|-------|-------------|---------------|
| 1 | AttackSurfaceFromNetwork | Reconnaissance | Maps endpoints, methods, params, auth from network log | Browse the app first |
| 2 | SecurityScan | Automated Scans | 10 passive audits: tech stack, CVEs, headers, CORS, XSS, cookies, etc. | Navigate to target page |
| 2 | JavaScriptVulnerabilities | Automated Scans | Focused Retire.js CVE scan for JS libraries | Navigate to target page |
| 2 | SecretsHarvest | Automated Scans | Credential/secret scan: JS bundles, cookies, storage, network, page text | Browse the app first |
| 2 | ThirdPartySecurity | Automated Scans | Third-party resources and SRI coverage | Navigate to target page |
| 2 | JwtAnalysis | Automated Scans | Decode JWTs from cookies/storage; flag alg, exp, sensitive claims | Log in first if needed |
| 2 | OidcFromNetwork | Automated Scans | OIDC discovery + provider audit; issuer auto-detect from network log | Browse / OIDC login first |
| 2 | JsAudit | Automated Scans | Fetch `script[src]` bundles; heuristic secret/debug/internal-URL scan | Navigate to target page |
| 3 | AutoScan | Active Testing | SQLi, IDOR, CSRF, path traversal, mass assignment scanners | Browse the app first |
| 3 | FirewallTest | Active Testing | CSP / SRI / sandbox / Permissions-Policy bypass attempts in the live page | Navigate to target page |
| 3 | GraphqlAnalysis | Active Testing | GraphQL security probes; endpoint auto-detect from network log | GraphQL traffic or public endpoint |
| 4 | SamlFromNetwork | SAML/Federation | Decode and analyze SAML messages from network log | Complete an SSO flow |
| 5 | HttpSmuggling | Advanced | Raw TCP smuggling timing probes vs. current document URL | Navigate to target origin |

---

## Trowser Twelve (orchestrated category playbooks)

**Where to find them:** Script Console → **Quicktests** → **Security** → **Trowser Twelve**.

These are separate from the numbered Phase 1–5 quicktests above. Each runs one **security playbook** — a curated chain of scanners for a single vulnerability category aligned with the Trowser Twelve taxonomy. Output is a colorized markdown report with severities, step metrics, and suggested `nextActions`.

**Prerequisites:**
1. Navigate to the target and browse key flows first (network log must be populated).

**Safety:** All Trowser Twelve quicktests default to `safetyMode: "safe"` — passive/read-only checks plus safe probes only. Edit the script and set `safetyMode: "active"` when you need live injection, fuzz, or fault-injection steps inside a playbook.

| Quicktest | Playbook ID | What it covers |
|-----------|-------------|----------------|
| A00 Full Site Security | `full` | All categories in sequence + attack-chain correlation |
| Quick LLM Sweep | `quick` | Attack-surface + A02 + A01 + A05 (safe) + federation decode (~60–120s) |
| A01 Access Control | `a01-access` | IDOR, authz, horizontal/vertical privilege |
| A02 Misconfiguration | `a02-misconfig` | Headers, CORS, cookies, discovery, methods |
| A03 Supply Chain | `a03-supplychain` | Retire.js, manifests, CI/CD, bundle fingerprinting |
| A04 Crypto and Secrets | `a04-crypto` | JWT hygiene, secrets harvest, session entropy |
| A05 Injection | `a05-injection` | SQLi, XSS, SSTI, CSTI, parser confusion |
| A06 Insecure Design | `a06-design` | Race conditions, business-logic indicators |
| A07 Authentication | `a07-authn` | Login flows, session handling, brute-force signals |
| A09 Operational Security | `a09-opsec` | Logging leaks, fail-open, debug exposure |
| A11 SSRF | `a11-ssrf` | Server-side request forgery probes |
| A12 Availability | `a12-availability` | Load/rate-limit indicators |
| A13 AI and LLM | `a13-llm` | LLM-specific risk patterns |
| A14 Other | `a14-other` | Catch-all / emerging checks |

**Start here:** Run **A00 Full Site Security** for a one-call assessment, then drill into individual categories for depth.

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
| CORS probing (deep) | Already in SecurityScan; standalone for targeted re-testing | REST/MCP or re-run SecurityScan |

**Tip:** Many of these are easier to use by asking the Trowser LLM in the chat. Say "test this login for SQL injection" and it will call the right APIs with the right parameters.
