# OWASP Top Ten Extended — Orchestration Categories

> **Purpose:** Grouping vulnerability types into orchestration-friendly "buckets"
> for a security testing tool targeting web services and APIs.
>
> **Source:** Condensed from an internal OWASP Top 25 for web services working list,
> cross-referenced against all historical OWASP Top 10 editions (2004–2025),
> OWASP Top 10 for LLM Applications (2025), and additional research.
>
> **Compiled: May 2026**

---

## Design Principles

- Each category maps to an **orchestration module** — a testable bucket a human
  or AI pentester can run independently.
- **Numbering follows OWASP Top Ten 2025** (A01–A07, A09) to avoid confusion.
  A08 is merged into A03 (both concern supply chain/integrity), and A10 is
  merged into A09 (both concern operational resilience). Extended categories
  continue from A11.
- AI/LLM Security gets its own category — the attack surface is growing fast
  and extends well beyond prompt injection.
- An "Other" category catches everything too small for its own module.
- Total: **12 categories** (with gaps at A08 and A10 to preserve OWASP alignment).

---

## Categories Overview

| ID | Category | OWASP Mapping | Module Focus |
|----|----------|---------------|--------------|
| A01 | Access Control & Authorization | A01:2025 | Who can access what |
| A02 | Security Misconfiguration | A02:2025 | Infrastructure and deployment hygiene |
| A03 | Supply Chain & Software Integrity | A03+A08:2025 | Dependencies, build pipeline, integrity |
| A04 | Cryptographic Failures & Secrets | A04:2025 | Data protection at rest and in transit |
| A05 | Injection | A05:2025 | Untrusted input interpreted as code/queries |
| A06 | Insecure Design & Business Logic | A06:2025 | Architectural and workflow flaws |
| A07 | Authentication & Session Management | A07:2025 | Proving identity, session integrity |
| — | *(A08 merged into A03)* | | |
| A09 | Operational Security | A09+A10:2025 | Logging, monitoring, error handling |
| — | *(A10 merged into A09)* | | |
| A11 | Server-Side Request Forgery (SSRF) | was A10:2021 | Server fetches attacker-controlled URLs |
| A12 | Availability & Resource Management | — | DoS, rate limiting, resource exhaustion |
| A13 | AI & LLM Security | OWASP LLM Top 10 | AI-integrated application risks |
| A14 | Other | — | Niche protocol/layer attacks |

---

## A01. Access Control & Authorization

**OWASP A01:2025 — Broken Access Control**

Tests whether the application correctly enforces *what* authenticated users are
allowed to do.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Broken Access Control (IDOR, privilege escalation, path traversal) | Top 25 #1 | Core of the category |
| Cross-Site Request Forgery (CSRF) | Top 25 #19 | Forces unintended authenticated actions |
| Mass Assignment / Excessive Data Exposure | Top 25 #24 | Accepts/returns more properties than authorized |
| Missing Function-Level Access Control | A01 sub-type | Admin endpoints accessible without checks |
| Cross-Site WebSocket Hijacking (CSWSH) | Research | WebSocket equivalent of CSRF |

### Testing Approach
- Horizontal/vertical privilege escalation checks
- IDOR enumeration across all object references
- CSRF token validation and SameSite cookie assessment
- Mass assignment fuzzing (add `isAdmin`, `role`, `price` fields)
- WebSocket origin validation

---

## A02. Security Misconfiguration

**OWASP A02:2025 — Security Misconfiguration**

Tests deployment and infrastructure configuration hygiene.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Default credentials, unnecessary services, verbose errors | Top 25 #2 | Core misconfiguration |
| Permissive CORS policies | Top 25 #2 | Allows cross-origin data theft |
| Improper API Inventory (Shadow/Zombie APIs) | Top 25 #20 | Unmonitored attack surface |
| Subdomain Takeover | Top 25 #25 | Dangling DNS → attacker content |
| Clickjacking / UI Redressing | HM #27 | Missing X-Frame-Options / CSP |
| Missing Security Headers (CSP, X-Content-Type, etc.) | A02 sub-type | Defense-in-depth gaps |
| Exposed admin panels, debug endpoints, directory listings | A02 sub-type | Information leakage |
| Container/Kubernetes misconfiguration | Research | Privileged containers, exposed dashboards |

### Testing Approach
- HTTP security header assessment
- Default credential and admin panel discovery
- CORS policy validation
- DNS record enumeration for dangling entries
- Cloud configuration review (S3 buckets, storage accounts)
- API endpoint discovery and inventory comparison

---

## A03. Supply Chain & Software Integrity

**OWASP A03+A08:2025 — Supply Chain Failures + Integrity Failures**

These two OWASP categories are merged because they share tooling (SCA scanners,
SBOM analysis) and both concern trust in external/upstream code. A08 (Software
and Data Integrity Failures) is folded in here rather than kept separate.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Vulnerable/outdated dependencies | Top 25 #3 | Known CVEs in libraries |
| Dependency confusion / typosquatting | Top 25 #3 | Malicious packages |
| Compromised build pipelines (CI/CD) | Top 25 #8 | SolarWinds pattern |
| Unsigned artifacts, unverified updates | Top 25 #8 | Missing integrity checks |
| Deserialization of Untrusted Data | Top 25 #13 | Java, PHP, Python, .NET deserialization → RCE |
| Unrestricted File Upload | Top 25 #12 | Executable files uploaded → web shells |

### Testing Approach
- Software Composition Analysis (SCA) for known vulnerabilities
- SBOM generation and review
- CI/CD pipeline security audit
- Deserialization endpoint detection and gadget chain testing
- File upload testing (type bypass, path traversal, execution)

---

## A04. Cryptographic Failures & Secrets Management

**OWASP A04:2025 — Cryptographic Failures**

Tests protection of sensitive data at rest, in transit, and in configuration.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Weak/deprecated algorithms (MD5, SHA1, DES, RC4) | Top 25 #4 | Core crypto failures |
| Missing or improper encryption (data at rest/transit) | Top 25 #4 | Plaintext storage, missing TLS |
| Poor key management (hardcoded, weak, unrotated) | Top 25 #4 | Keys in source, shared secrets |
| Secrets & Credential Exposure | Top 25 #14 | .env files, git history, error pages |
| Insufficient Transport Layer Security | HM #26 | Missing HSTS, TLS 1.0/1.1, weak ciphers |
| Insecure random number generation | CWE-330 | Predictable tokens, nonces |

### Testing Approach
- TLS configuration scanning (cipher suites, protocol versions, HSTS)
- Source code and git history scanning for secrets
- Entropy analysis of tokens and session identifiers
- Certificate validation and pinning assessment
- Data-at-rest encryption verification

---

## A05. Injection

**OWASP A05:2025 — Injection**

Tests whether untrusted input is interpreted as code, queries, or markup by any
interpreter in the stack.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| SQL / NoSQL / ORM Injection | Top 25 #5 | Classic injection, still #1 breach cause |
| OS Command Injection | Top 25 #5 | Shell metacharacter exploitation |
| Cross-Site Scripting (XSS) — Stored, Reflected, DOM | Top 25 #18 | Client-side injection |
| Server-Side Template Injection (SSTI) | Top 25 #16 | Jinja2, Freemarker, Twig → RCE |
| XML External Entity (XXE) Processing | Top 25 #21 | Entity expansion, file read, SSRF |
| LDAP / XPath / Header Injection | A05 sub-types | Less common but same pattern |
| Prototype Pollution (JavaScript) | HM #30 | Object.prototype modification → XSS/RCE |
| Expression Language Injection (EL/SpEL) | Research | Java/Spring expression evaluation |

### Testing Approach
- Context-aware payload injection across all input vectors
- Blind injection detection (time-based, out-of-band)
- DOM source/sink analysis for client-side injection
- Template syntax detection and exploitation
- XML parser configuration assessment

---

## A06. Insecure Design & Business Logic

**OWASP A06:2025 — Insecure Design**

Tests architectural decisions and workflow logic that cannot be fixed by patching
a single function — they require redesign.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Missing threat modeling / defense-in-depth | Top 25 #6 | Core design failures |
| Business Logic Flaws | Top 25 #15 | Price manipulation, workflow bypass |
| Race Conditions (TOCTOU) | Top 25 #17 | Double-spend, parallel exploitation |
| Step-skipping in multi-stage processes | Top 25 #15 | Checkout/verification bypass |
| Insufficient anti-automation | Research | Bot abuse of legitimate features |

### Testing Approach
- Workflow analysis: can steps be skipped, reordered, or replayed?
- Concurrent request testing (race conditions)
- Numeric/pricing manipulation
- State machine analysis for impossible transitions
- Abuse case modeling for each business feature

---

## A07. Authentication & Session Management

**OWASP A07:2025 — Authentication Failures**

Tests the mechanisms that prove user identity and maintain authenticated state.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Authentication Failures (weak passwords, missing MFA, credential stuffing) | Top 25 #7 | Core of the category |
| JWT Algorithm Confusion & Claim Tampering | Research | `alg:none`, weak secrets, unvalidated claims |
| OAuth/OIDC Misconfiguration | Research | Redirect URI hijacking, token leakage, confused deputy |
| Session Fixation & Management Flaws | A07 sub-type | Predictable tokens, missing invalidation |
| Credential Stuffing & Brute-Force | Top 25 #7 | Overlaps with rate limiting (A12) |

### Testing Approach
- Password policy and lockout mechanism testing
- JWT signature verification, algorithm switching, claim manipulation
- OAuth flow testing (authorization code interception, redirect URI validation)
- Session token entropy, rotation, and invalidation
- MFA bypass attempts

---

## A09. Operational Security

**OWASP A09+A10:2025 — Logging/Alerting Failures + Exceptional Conditions**

Merged because both concern how the application behaves during and after
abnormal conditions — the "observability and resilience" bucket. A10 (Mishandling
of Exceptional Conditions) is folded in here rather than kept separate.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Security Logging & Alerting Failures | Top 25 #9 | Undetected breaches |
| Mishandling of Exceptional Conditions | Top 25 #10 | Failing open, info leakage in errors |
| Sensitive data in error messages/stack traces | A10 sub-type | Exposes internals to attackers |
| Missing audit trail for security-relevant actions | A09 sub-type | Non-repudiation failures |
| Inadequate incident response capability | A09 sub-type | No alerting = no response |

### Testing Approach
- Trigger errors and analyze responses for information leakage
- Verify security events are logged (failed auth, access control violations)
- Test fail-open vs. fail-closed behavior
- Assess log integrity and tamper protection
- Verify alerting fires on suspicious patterns

---

## A11. Server-Side Request Forgery (SSRF)

**Formerly OWASP A10:2021 — standalone due to catastrophic cloud impact**

Separated from generic injection because SSRF requires distinct detection
techniques and is catastrophically impactful in cloud environments.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| SSRF to cloud metadata endpoints | Top 25 #11 | 169.254.169.254, GCP, Azure equivalents |
| SSRF via URL parameters, webhooks, file imports | Top 25 #11 | Any feature that fetches URLs |
| Blind SSRF (out-of-band detection) | Top 25 #11 | No direct response but side-channel |
| DNS Rebinding | Research | Bypasses SSRF allowlists via DNS TTL manipulation |
| Insecure Webhook/Callback Endpoints | HM #32 | Redirect callbacks to attacker servers |

### Testing Approach
- Identify all URL-accepting parameters (imports, previews, webhooks, integrations)
- Probe for cloud metadata access (AWS, GCP, Azure)
- Test allowlist/blocklist bypass (IP encoding, DNS rebinding, redirects)
- Out-of-band interaction detection (Burp Collaborator, interactsh)

---

## A12. Availability & Resource Management

**No direct OWASP Top Ten mapping — addresses denial-of-service and abuse**

Tests whether the application can withstand intentional resource exhaustion or
abuse at scale.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Insufficient Rate Limiting | Top 25 #22 | Brute-force, scraping, enumeration |
| Resource Exhaustion (CPU, memory, connections) | Top 25 #22 | ReDoS, zip bombs, large payloads |
| GraphQL-Specific DoS (nested queries, batching) | HM #29 | Query complexity exploitation |
| API Abuse at Scale | Research | Legitimate endpoints used maliciously |
| Algorithmic Complexity Attacks (HashDoS, ReDoS) | CWE-400 | Triggering worst-case algorithms |

### Testing Approach
- Rate limit identification and bypass testing
- Large payload and nested query fuzzing
- Regex complexity analysis (ReDoS)
- Connection pool exhaustion testing
- GraphQL introspection and query cost analysis

---

## A13. AI & LLM Security

**OWASP Top 10 for LLM Applications (2025)**

Dedicated category for applications integrating AI/LLM capabilities. The attack
surface extends far beyond prompt injection — covering output handling, tool use,
data poisoning, and autonomous agent risks. This category will only grow as AI
integration becomes ubiquitous in web services.

### Vulnerability Types

| Vulnerability | Source | Notes |
|---|---|---|
| Prompt Injection (Direct & Indirect) | OWASP LLM01 | Manipulating LLM behavior via crafted input |
| Insecure Output Handling | OWASP LLM02 | LLM outputs rendered without sanitization → XSS, injection |
| Training Data Poisoning | OWASP LLM03 | Corrupted training data → biased/malicious responses |
| Sensitive Information Disclosure | OWASP LLM05 | LLM leaks PII, secrets, or proprietary data from training |
| Insecure Plugin / Tool Use | OWASP LLM06 | AI calling external tools without proper sandboxing |
| Excessive Agency | OWASP LLM07 | AI agents with overly broad permissions, insufficient guardrails |
| Model Denial of Service | OWASP LLM04 | Resource exhaustion via crafted prompts |
| Model Theft / Inversion | OWASP LLM10 | Extracting model weights or reconstructing training data |
| Indirect Prompt Injection via Data Sources | Research | Poisoned documents/emails trigger actions when processed |
| AI Supply Chain (compromised models, datasets) | OWASP LLM09 | Backdoored fine-tuned models, poisoned embeddings |

### Testing Approach
- Prompt injection testing (direct, indirect via documents/context)
- Output sanitization validation (does LLM output get rendered unsafely?)
- Tool/plugin permission boundary testing
- Data exfiltration attempts via conversational manipulation
- Agent guardrail testing (can the AI be tricked into unauthorized actions?)
- Model resource exhaustion (long contexts, recursive generation)
- Assess what data the LLM has access to vs. what it should have

---

## A14. Other

**Catch-all for protocol-layer and niche attacks that don't justify their own
orchestration module due to limited applicability or specialized prerequisites.**

| Vulnerability | Source | Notes |
|---|---|---|
| Web Cache Poisoning | Top 25 #23 | Manipulating unkeyed headers → cached malicious responses |
| HTTP Request Smuggling | HM #28 | Parser desync between front-end and back-end |
| Open Redirect | HM #33 | OAuth token theft, phishing enabler |
| HTTP/2 & HTTP/3 Protocol Attacks | Research | Not implemented in Trowser (no h2c / CONTINUATION / H2.CL). ALPN is fingerprinted only. |
| WebSocket Message Injection | Research | Input validation failures in WS messages |

### When to Promote
Move a vulnerability from "Other" to its own category when:
- It becomes a frequent finding in assessments
- Dedicated tooling emerges that justifies a separate scan module
- Impact/prevalence justifies orchestration-layer priority

---

## Mapping: Original Top 25 + Honorable Mentions → Categories

| Top 25 # | Vulnerability | Category |
|---|---|---|
| 1 | Broken Access Control | A01. Access Control |
| 2 | Security Misconfiguration | A02. Misconfiguration |
| 3 | Software Supply Chain Failures | A03. Supply Chain |
| 4 | Cryptographic Failures | A04. Crypto & Secrets |
| 5 | Injection | A05. Injection |
| 6 | Insecure Design | A06. Design & Logic |
| 7 | Authentication Failures | A07. Authentication |
| 8 | Software/Data Integrity Failures | A03. Supply Chain *(merged)* |
| 9 | Logging & Alerting Failures | A09. Operational Security |
| 10 | Mishandling Exceptional Conditions | A09. Operational Security *(merged)* |
| 11 | SSRF | A11. SSRF |
| 12 | Unrestricted File Upload | A03. Supply Chain |
| 13 | Deserialization | A03. Supply Chain |
| 14 | Secrets & Credential Exposure | A04. Crypto & Secrets |
| 15 | Business Logic Flaws | A06. Design & Logic |
| 16 | SSTI | A05. Injection |
| 17 | Race Conditions | A06. Design & Logic |
| 18 | XSS | A05. Injection |
| 19 | CSRF | A01. Access Control |
| 20 | Shadow/Zombie APIs | A02. Misconfiguration |
| 21 | XXE | A05. Injection |
| 22 | Rate Limiting & Resource Exhaustion | A12. Availability |
| 23 | Web Cache Poisoning | A14. Other |
| 24 | Mass Assignment | A01. Access Control |
| 25 | Subdomain Takeover | A02. Misconfiguration |
| HM 26 | Insufficient Transport Layer Security | A04. Crypto & Secrets |
| HM 27 | Clickjacking / UI Redressing | A02. Misconfiguration |
| HM 28 | HTTP Request Smuggling | A14. Other |
| HM 29 | GraphQL-Specific Attacks | A12. Availability |
| HM 30 | Prototype Pollution | A05. Injection |
| HM 31 | AI/LLM Prompt Injection | A13. AI & LLM |
| HM 32 | Insecure Webhook/Callback Endpoints | A11. SSRF |
| HM 33 | Open Redirect | A14. Other |

---

## Additional Vulnerabilities Added (Not in Original Top 25)

| Vulnerability | Category | Rationale |
|---|---|---|
| JWT Algorithm Confusion & Claim Tampering | A07. Authentication | Critical in modern API auth |
| OAuth/OIDC Misconfiguration | A07. Authentication | Primary auth protocol for web services |
| DNS Rebinding | A11. SSRF | SSRF allowlist bypass technique |
| Expression Language Injection (EL/SpEL) | A05. Injection | Common in Java/Spring environments |
| Container/Kubernetes Misconfiguration | A02. Misconfiguration | Modern deployment reality |
| Algorithmic Complexity Attacks (ReDoS, HashDoS) | A12. Availability | Targeted resource exhaustion |
| Cross-Site WebSocket Hijacking (CSWSH) | A01. Access Control | WebSocket equivalent of CSRF |
| HTTP/2 & HTTP/3 Protocol Attacks | A14. Other | Emerging protocol-layer risks |
| Insecure Random Number Generation | A04. Crypto & Secrets | Predictable tokens/nonces |
| Insecure Output Handling (LLM) | A13. AI & LLM | LLM output rendered without sanitization |
| Training Data Poisoning | A13. AI & LLM | Corrupted training → malicious behavior |
| Insecure Plugin / Tool Use (AI) | A13. AI & LLM | AI calling tools without sandboxing |
| Excessive Agency (AI Agents) | A13. AI & LLM | Overly broad AI permissions |
| Model Theft / Inversion | A13. AI & LLM | Extracting proprietary model data |
| Indirect Prompt Injection | A13. AI & LLM | Poisoned data sources trigger AI actions |

---

## Historical OWASP Cross-Reference

Verified against all OWASP Top 10 editions (2004, 2007, 2010, 2013, 2017, 2021,
2025) to ensure no significant historical vulnerability type is uncovered.

| Historical Item | Status in This Framework |
|---|---|
| Unvalidated Input (2004) | ✅ Covered by A05. Injection |
| Buffer Overflows (2004) | ⚠️ Rare in modern web services; out of scope |
| Improper Error Handling (2004, 2007) | ✅ Covered by A09. Operational Security |
| Insecure Storage (2004) | ✅ Covered by A04. Crypto & Secrets |
| Denial of Service (2004) | ✅ Covered by A12. Availability |
| Information Leakage (2007) | ✅ Split across A04. Crypto, A09. Ops Security |
| Insecure Communications (2007) | ✅ Covered by A04. Crypto (TLS) |
| Failure to Restrict URL Access (2007, 2010) | ✅ Covered by A01. Access Control |
| Insecure Direct Object References (2007–2013) | ✅ Covered by A01. Access Control (IDOR) |
| Unvalidated Redirects & Forwards (2010, 2013) | ✅ Covered by A14. Other (Open Redirect) |
| Missing Function-Level Access Control (2013) | ✅ Covered by A01. Access Control |
| Using Components with Known Vulns (2013, 2017) | ✅ Covered by A03. Supply Chain |
| XML External Entities / XXE (2017) | ✅ Covered by A05. Injection |
| Insecure Deserialization (2017) | ✅ Covered by A03. Supply Chain |
| Insufficient Logging & Monitoring (2017, 2021) | ✅ Covered by A09. Operational Security |
| SSRF (2021) | ✅ Covered by A11. SSRF (standalone) |
| Insecure Design (2021) | ✅ Covered by A06. Design & Logic |

**Result:** No gaps identified. All historically significant OWASP categories
are represented in the 12-category framework.

---

## Usage in Orchestration Layer

```
┌───────────────────────────────────────────────────────────────────────┐
│                      ORCHESTRATION CONTROLLER                          │
├───────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                 │
│  │ A01.     │ │ A02.     │ │ A03.     │ │ A04.     │                 │
│  │ Access   │ │ Config   │ │ Supply   │ │ Crypto   │                 │
│  │ Control  │ │          │ │ Chain    │ │ Secrets  │                 │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘                 │
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                 │
│  │ A05.     │ │ A06.     │ │ A07.     │ │ A09.     │                 │
│  │ Inject   │ │ Design   │ │ AuthN    │ │ Ops      │                 │
│  │          │ │ Logic    │ │ Session  │ │ Security │                 │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘                 │
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                 │
│  │ A11.     │ │ A12.     │ │ A13.     │ │ A14.     │                 │
│  │ SSRF     │ │ Avail-   │ │ AI &     │ │ Other    │                 │
│  │          │ │ ability  │ │ LLM      │ │          │                 │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘                 │
│                                                                         │
│  Note: A08 merged into A03, A10 merged into A09                        │
│                                                                         │
└───────────────────────────────────────────────────────────────────────┘
```

Each module can be:
- Run independently or in parallel
- Scoped to specific endpoints/features
- Conditionally included (e.g., skip "A13. AI & LLM" if no AI integration,
  skip "A12. Availability" for internal tools, emphasize "A01. Access Control"
  for multi-tenant SaaS)

---

## References

- [OWASP Top 10 (2025)](https://owasp.org/Top10/2025/)
- [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [OWASP Testing Guide v5](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25 (2024)](https://cwe.mitre.org/top25/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10 History (2004–2025)](https://owasp.org/www-project-top-ten/)
