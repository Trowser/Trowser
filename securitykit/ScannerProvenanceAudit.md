# Scanner Provenance & Quality Audit

Living tracker for security probes. Trowser owns the implementations; primary methodology citations are OWASP WSTG, PortSwigger, OWASP API Security, RFCs, and vendor advisories. pentest-ai is a secondary historical influence only.

See also: [SecurityTestingWithTrowser.md](../trowserkit/SecurityTestingWithTrowser.md) (Scanner provenance).

## Rubric (per artifact)

| # | Criterion | Pass means |
|---|-----------|------------|
| 1 | Attribution | “Inspired by …” / “influenced by”; no “Ported from/of” |
| 2 | Authority sources | ≥1 WSTG / PortSwigger / OWASP API / RFC / advisory in header |
| 3 | Detection contract | Hit oracle documented (baseline, canary, status, persistence, …) |
| 4 | False-positive discipline | Hard rejects / session reqs / non-destructive notes where material |
| 5 | Safety alignment | Matches active-vs-passive / mutation expectations |
| 6 | Standards on findings | Category maps in `VpxExportService.MapOwaspCwe` |
| 7 | API/docs parity | REST/MCP blurb accurate; no leftover “Ported from” |
| 8 | Known limits | Explicit “does not claim X” where evidence is weak |

Gaps: **P0** wrong/dangerous/high FP · **P1** missed strong oracle · **P2** docs/attribution polish.

Status: `open` / `fixed` / `accepted` (intentional limit).

---

## Artifact scorecard

Legend: P = pass. Scores reflect **post-audit** state.

| Artifact | Attr | Auth | Detect | FP | Safety | CWE | Docs | Limits | Gaps |
|----------|------|------|--------|----|--------|-----|------|--------|------|
| AccountEnumerationScanProbe | P | P | P | P | P | P | P | P | — |
| AssetSecretsCommentMiner | P | P | P | P | P | P | P | P | — |
| BflaAdminProbe | P | P | P | P | P | P | P | P | — |
| CacheDeceptionScanner | P | P | P | P | P | P | P | P | — |
| CacheHeaderAnalyzer | P | P | P | P | P | n/a | P | P | — |
| CacheMapScanner | P | P | P | P | P | P | P | P | — |
| CachePollutionScanner | P | P | P | P | P | P | P | P | — |
| CachePoisonScanner | P | P | P | P | P | P | P | P | — |
| CaptchaReplayScanProbe | P | P | P | P | P | P | P | P | — |
| CookiePrefixBypassChecker | P | P | P | P | P | P | P | P | — |
| DeserializationScanProbe | P | P | P | P | P | P | P | P | — |
| FileUploadScanProbe | P | P | P | P | P | P | P | P | — |
| ForcedErrorScanner | P | P | P | P | P | P | P | P | — |
| HttpRequestSmugglingScanner | P | P | P | P | P | P | P | P | confirmed = differential 404; TE body / Via / CL-CL are notes |
| JwtHeaderAbuseProbe | P | P | P | P | P | P | P | P | accepted: L1 |
| LdapScanProbe | P | P | P | P | P | P | P | P | — |
| MassAssignmentExtendedProbes | P | P | P | P | P | P | P | P | — |
| NextJsRscScanProbe | P | P | P | P | P | P | P | P | accepted: L3 |
| NosqlScanProbe | P | P | P | P | P | P | P | P | — |
| PasswordResetWeakScanProbe | P | P | P | P | P | P | P | P | — |
| PrototypePollutionScanProbe | P | P | P | P | P | P | P | P | accepted: L2 |
| RaceConditionScanProbe | P | P | P | P | P | P | P | P | — |
| SqliLoginSweep | P | P | P | P | P | P | P | P | — |
| SstiPolyglotScanProbe | P | P | P | P | P | P | P | P | — |
| SstiStoredScanProbe | P | P | P | P | P | P | P | P | — |
| TrustedHeaderBypassChecker | P | P | P | P | P | P | P | P | — |
| UploadXxeProbe | P | P | P | P | P | P | P | P | — |
| InjectionScaffold | P | P | n/a | n/a | P | n/a | P | P | — |
| RateLimitRespectHelper | P | P | n/a | n/a | P | n/a | P | P | — |
| LlmHttpAdapter | P | P | n/a | n/a | P | n/a | P | P | — |
| CveReachabilityRunner | P | P | P | P | P | P | P | P | — |
| API/methodology docs | P | P | n/a | n/a | n/a | n/a | P | P | — |

---

## Source matrix (primary → secondary)

| Family | Primary | Secondary (historical) |
|--------|---------|--------------------------|
| SSTI | WSTG-INPV-18; PortSwigger SSTI | pentest-ai `web.ssti_*` |
| Prototype pollution | WSTG-INPV-22; PortSwigger Research | `web.prototype_pollution` |
| Mass assignment | WSTG-INPV-20; OWASP API | `web.mass_assignment` / `privilege_escalation_patch` |
| LDAP | WSTG-INPV-06 | `web.ldap_injection` |
| NoSQL | WSTG-INPV-05.6 | `web.nosql_fuzz` |
| SQLi login | WSTG-INPV-05; PortSwigger SQLi | `web.sqli_login_bypass` |
| XXE upload | WSTG-INPV-07; OWASP XXE CS | `web.xxe_upload` |
| Deserialization | OWASP Deserialization CS | `web.deserialization` |
| File upload | WSTG upload testing | `web.file_upload_validation` |
| Race | PortSwigger race conditions | `web.race_condition` |
| JWT header abuse | PortSwigger JWT; RFC 7515/7517 | `web.jwt_jku_x5u_ssrf` |
| Cookie prefixes | RFC 6265bis | `web.cookie_prefix_bypass` |
| Cache deception | PortSwigger cache deception | `web.cache_deception` |
| HTTP request smuggling | PortSwigger HTTP request smuggling (CL.TE/TE.CL differential); RFC 9110/9112 | — |
| Cache map / pollution | PortSwigger web cache poisoning (key construction, unkeyed headers) | — |
| Account enum | WSTG IDNT/ATHN | `web.user_enum` |
| BFLA | OWASP API5 | `_bfla_admin` |
| Trusted headers | WSTG access-control | `web.trusted_header_bypass` |
| Forced error | WSTG error handling | `web.forced_error` |
| Captcha replay | WSTG CAPTCHA / business logic | `web.captcha_replay` |
| Password reset | WSTG password-reset | `web.password_reset_weak` |
| Next.js RSC | Vendor/CVE advisories | `web.nextjs_rsc_rce` |
| Asset secrets | Secret-scanning practice; OWASP secrets | `web.asset_secrets_scan` |
| Injection scaffold | WSTG common entry points | ALWAYS_PROBED pattern |
| Rate-limit helper | RFC 6585 / Retry-After | `_safety.py` pattern |
| LLM HTTP adapter | OWASP LLM Top 10 (application-layer) | `agents/llm_redteam/adapter.py` |
| LLM unbounded consumption | OWASP LLM10:2025 | A12 rate-limit / body-size patterns |
| LLM RAG/memory poison | OWASP LLM04/LLM08:2025 | Indirect injection + peer chat |
| CVE reachability | Vendor advisories / PoC patterns | `cve_poc_primitives.py` |

---

## Change log (audit work)

| Date | Change |
|------|--------|
| 2026-08-20 | HttpRequestSmugglingScanner: FP discipline — TE-TE no body equality; CL-CL/HEADER observation; Via-only passive not elevated; verdict confirmed\|unconfirmed\|clean |
| 2026-07-26 | Initial tracker; full attribution reframe; quality harden waves 1–4; VPX CWE gaps; docs |

### Wave notes

#### Wave 1 — Injection
- SSTI polyglot: non-digit boundary for `49`; severity demotion for partial/residue.
- SSTI stored: baseline marker absence; echo→high, readback→critical.
- Prototype pollution: GET canary emergence per verify URL.
- NoSQL: error oracle requires clean baseline.
- LDAP / SQLi login: weak status-flip → medium; strong signals → high/critical.
- XXE upload: DoS needs timing + status/body corroboration.
- Deserialization: removed `[object Object]`; time-only → high.
- Next.js RSC: category `nextjs-rsc-rce`; tightened markers; sleep baseline delta.

#### Wave 2 — Authz / session
- Cookie prefix oracle fixed (session vs cookieless).
- BFLA: anon differential; empty 204 → medium; category `bfla`.
- JWT: critical without admin-only gate; renamed non-OOB “SSRF” claims.
- Password reset: removed bare `reset` success oracle.
- Mass assignment: JSON key persistence; reflection ≤ medium.
- Trusted headers: SPA shell + body≠baseline.
- Account enum: timing-only → low.
- Captcha: reject phrases not Accepted on 2xx.

#### Wave 3 — Cache / upload / misc
- Cache deception: auth delta + anon≈authed + cache signal for confirmed; current path always included.
- Cache map: busted query/path indication only; does not claim live-key poison.
- Cache pollution: miss-forcing header + error store + clean GET; no query buster fallback.
- Race: sequential baseline gate; distinct ids for high.
- Forced error: ASP.NET yellow screen → medium verbose-error.
- Upload persistence: tighter signals (no bare multipart/filename).
- Asset secrets: hygiene keywords → info `comment-hygiene`.

#### Wave 4 — Helpers / docs / VPX
- Rate-limit helper: record 429 only after final failure.
- LLM adapter: empty string on unexpected schema (no JSON dump).
- MapOwaspCwe: added missing categories (file-upload-*, xxe-upload, jwt-header-abuse, nextjs-rsc-rce, …).
- InjectionScaffold restored (corruption during parallel edits) with inspired-by header.
- CveReachabilityRunner attribution updated.
- Methodology provenance section + API/MCP/OpenAPI wording; CHANGELOG Unreleased.

### Open / accepted limits

| ID | Severity | Artifact | Note |
|----|----------|----------|------|
| L1 | accepted | JwtHeaderAbuseProbe | jku/x5u canary URLs indicate *acceptance* of attacker-controlled header values, not out-of-band SSRF confirmation |
| L2 | accepted | PrototypePollutionScanProbe | Echo-canary emergence; does not implement PortSwigger json-spaces / status-code override gadgets |
| L3 | accepted | NextJsRscScanProbe | Tied to specific RSC advisory signatures; re-validate when CVE mapping changes |

### Fixed during audit

| ID | Was | Artifact | Fix |
|----|-----|----------|-----|
| F1 | P2 | All Ported-from headers | Rewrote to Inspired-by multi-source |
| F2 | P2 | API / MCP / OpenAPI | Removed “Ported from” / pentest-ai-style primary claims |
| F3 | P1 | VPX MapOwaspCwe | Added missing categories used by these probes |
| F4 | P0/P1 | CookiePrefix, CacheDeception, Race, BFLA, oracles | See wave notes |
| F5 | P1 | JwtHeaderAbuseProbe | Severity/confidence wording: canary ≠ confirmed SSRF |
| F6 | P0 | InjectionScaffold truncation | Reconstructed from call sites + prior transcript history |
