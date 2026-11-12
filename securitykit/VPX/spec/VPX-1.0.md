# VPX 1.0 — Vulnerability Proof eXchange

**Status:** Published (superseded for new documents by [VPX 1.1](./VPX-1.1.md))  
**Version:** 1.0  
**Date:** 2026-05-23  
**Schema:** [`../schema/vpx-1.0.schema.json`](../schema/vpx-1.0.schema.json)

---

## 1. Introduction

### 1.1 Purpose

VPX (Vulnerability Proof eXchange) is a JSON document format for exchanging information between:

- **Hypothesis producers** — source-code analysis, LLM review, static scanners
- **Proof executors** — browser-based testers, authenticated API fuzzers, workflow verifiers
- **Triage consumers** — developers, fix agents, risk dashboards

VPX documents **what is needed to prioritize, prove, and remediate** application vulnerabilities — and nothing more.

### 1.2 Scope

VPX targets **web application vulnerabilities** — issues reachable or discoverable through HTTP surfaces, web APIs, and their supporting server-side code. Surfaces are modeled as HTTP endpoints (route + method); findings bind to those surfaces or to source-code locations within web application codebases.

VPX is not designed for native-binary, mobile, embedded, or desktop-application vulnerability analysis. Producers SHOULD verify the target is a web application before emitting VPX output.

VPX does **not** define:

- Software bill of materials or dependency CVE inventory
- Generic static-analysis rule catalogs
- Transport protocols or API endpoints (implementers choose)

### 1.3 Design heuristic

> **Document what is needed, but not more than that.**

Every field in VPX must earn its place by enabling hypothesis → proof → verdict → fix. Optional fields exist only when they reduce ambiguity for the next actor in the pipeline.

### 1.4 Conformance

A VPX document **MUST**:

1. Be UTF-8 JSON.
2. Include `vpxVersion` with value `"1.0"`.
3. Include a unique `documentId` (UUID recommended).
4. Include all four top-level arrays: `surfaces`, `findings`, `proofs`, `verdicts` (each MAY be empty).
5. Validate against the normative JSON Schema unless explicitly using a documented profile subset.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Hypothesis** | A reported vulnerability that has not yet been proven or disproven at runtime. |
| **Surface** | An HTTP-accessible entry point: route, method, parameters, and auth context. |
| **Proof** | A recorded attempt to verify exploitability under realistic session conditions. |
| **Verdict** | Triage outcome: exploitability status, disposition, and optional remediation hints. |
| **Producer** | Tool or agent that creates or updates VPX documents. |
| **Executor** | Tool that runs proofs against a live target. |

---

## 3. Document model

### 3.1 Root object

| Field | Required | Description |
|-------|----------|-------------|
| `vpxVersion` | yes | Format version. Must be `"1.0"`. |
| `documentId` | yes | Stable identifier for this document instance. |
| `createdAt` | no | ISO 8601 UTC timestamp of first creation. |
| `updatedAt` | no | ISO 8601 UTC timestamp of last modification. |
| `profile` | no | Profile in use: `compact`, `full`, or `summary`. |
| `target` | no | Deployment under test. |
| `policy` | no | Organizational triage rules. |
| `surfaces` | yes | Attack surface catalog. May be `[]`. |
| `findings` | yes | Vulnerability hypotheses. May be `[]`. |
| `proofs` | yes | Proof execution records. May be `[]`. |
| `verdicts` | yes | Triage outcomes. May be `[]`. |

### 3.2 Target

Describes the application instance proofs apply to.

```json
{
  "baseUrl": "https://staging.example.com",
  "repository": "github.com/acme/webapp",
  "commit": "abc123def",
  "environment": "staging"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `baseUrl` | no | Origin URL for relative routes in surfaces. |
| `repository` | no | Source repository URI or path. |
| `commit` | no | Git commit SHA or tag. |
| `environment` | no | Free-form: `production`, `staging`, `local`, etc. |

### 3.3 Policy

Optional triage constraints. Executors MAY use these to order proof queues.

```json
{
  "cvssCap": 7.0,
  "proofRequiredAbove": "medium",
  "deferBelowPriority": 40
}
```

| Field | Description |
|-------|-------------|
| `cvssCap` | Findings below this CVSS MAY be deferred without proof. |
| `proofRequiredAbove` | Severity threshold requiring proof before acceptance. |
| `deferBelowPriority` | Findings with `proofPriority` below this MAY auto-defer. |

---

## 4. Surfaces

A **surface** is a deduplicated runtime entry point. Multiple findings MAY reference the same `surfaceId`.

### 4.1 Surface object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. Recommended: short slug (`surf-users-search`). |
| `route` | yes | Path (`/api/users`) or absolute URL. |
| `method` | yes | HTTP method (`GET`, `POST`, …). |
| `params` | no | Input parameters (see §4.2). |
| `auth` | no | Authentication context (see §4.3). |

### 4.2 Parameter

```json
{ "name": "q", "in": "query", "type": "string" }
```

| Field | Required | Values |
|-------|----------|--------|
| `name` | yes | Parameter name. |
| `in` | yes | `query`, `body`, `path`, `header`, `cookie` |
| `type` | no | `string`, `number`, `boolean`, `object`, `array` |

### 4.3 Auth

```json
{ "required": true, "roles": ["user"], "mechanism": "session-cookie" }
```

| Field | Description |
|-------|-------------|
| `required` | Whether authentication is needed to reach the surface. |
| `roles` | Roles or scopes that can access the surface. |
| `mechanism` | Free-form: `session-cookie`, `bearer-jwt`, `api-key`, `none`, etc. |

---

## 5. Findings

A **finding** is a vulnerability hypothesis.

### 5.1 Required fields

| Field | Description |
|-------|-------------|
| `id` | Unique within document. |
| `kind` | Vulnerability category (see §5.4). |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `title` | Short human-readable summary. |
| `description` | Human-readable description of the vulnerability (max 2000 chars). Separates "what this is" from `investigationHints` "how to investigate". Optional but recommended. |
| `status` | Lifecycle state (see §5.5). |

### 5.2 Surface binding

| Field | Description |
|-------|-------------|
| `surfaceId` | Reference to `surfaces[].id`. |
| `surfaceIds` | Array of additional surface IDs when a finding spans multiple surfaces. Use alongside or instead of `surfaceId`. |
| `param` | Parameter name on that surface implicated in the vulnerability. |

At least one of `surfaceId` or `origin` SHOULD be present. Both MAY be present. When a finding affects multiple surfaces, use `surfaceIds` to list them all; `surfaceId` MAY contain the primary surface.

### 5.3 Origin (static context)

```json
{
  "tool": "llm-sast",
  "rule": "CWE-89",
  "file": "src/Api/UserSearchController.cs",
  "line": 87,
  "snippet": "var sql = $\"SELECT ... {q} ...\";"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `tool` | yes | Producer name (`llm-sast`, `semgrep`, `codeql`, `trowser-shadow`, …). |
| `rule` | no | Rule ID or CWE reference. |
| `file` | no | Source file path. |
| `line` | no | Line number (1-based). |
| `snippet` | no | Relevant code excerpt. Keep under 500 characters in compact profile. |

### 5.4 Trace

`trace` is an ordered array of short strings describing data or control flow. **Maximum 8 entries** in full profile; **5 in compact**.

```json
[
  "Request.Query[\"q\"] → SearchController.Search",
  "→ BuildSearchQuery(q)",
  "→ SqlCommand.ExecuteReader"
]
```

### 5.5 Kind (category)

Use lowercase kebab-case. Common values:

`sqli`, `xss`, `csrf`, `idor`, `ssrf`, `open-redirect`, `path-traversal`, `mass-assignment`, `ssti`, `command-injection`, `deserialization`, `header-injection`, `auth-bypass`, `info-leak`, `misconfiguration`, `other`

Producers MAY emit additional kinds; consumers MUST accept unknown kinds without failing.

### 5.6 Status (finding lifecycle)

| Value | Meaning |
|-------|---------|
| `hypothesis` | Reported, not yet tested at runtime. |
| `under_investigation` | Proof queued or in progress. |
| `deferred` | Below policy threshold; proof not scheduled. |

After proof, update via `verdicts[]` — do not overload `findings[].status` with exploitability outcomes.

### 5.7 Proof hints

Hints for executors. Omit fields unknown to the producer.

```json
{
  "category": "sqli",
  "payloads": ["' OR '1'='1"],
  "oracle": "error-or-timing",
  "identity": "authenticated-user"
}
```

| Field | Description |
|-------|-------------|
| `category` | Normalized scanner category (often matches `kind`). |
| `payloads` | Suggested injection strings (max 5 in compact). |
| `oracle` | Expected signal: `error`, `timing`, `reflection`, `dom-change`, `status-code`, `network-match`, etc. |
| `identity` | Session needed: `anonymous`, `authenticated-user`, `admin`, or named identity. |

### 5.8 Scoring (optional)

| Field | Range | Description |
|-------|-------|-------------|
| `cvss` | 0.0–10.0 | Theoretical severity from static analysis. |
| `confidence` | 0.0–1.0 | Producer confidence in this hypothesis. Note: `verdicts[].confidence` measures a different thing — certainty in the triage outcome after proof. |
| `proofPriority` | 0–100 | Suggested proof queue priority (higher = prove first). |

### 5.9 Classification (optional)

| Field | Description |
|-------|-------------|
| `owasp` | OWASP category identifier (e.g. `A01`, `A05`). |
| `cwe` | Array of CWE identifiers (e.g. `["CWE-89"]`). Use this for standard taxonomy; keep `origin.rule` for scanner-specific rule IDs. |
| `reference` | URL or identifier for external reference (advisory, documentation). |
| `remediation` | Short remediation guidance as prose (max 2000 chars). For structured remediation with fix locations and code hints, use `verdicts[].remediation`. |

### 5.10 Relationships (optional)

| Field | Description |
|-------|-------------|
| `relatedFindingIds` | Array of finding `id` values that interact with this finding (e.g. attack chains, amplification). |
| `tags` | Free-form string labels for filtering and grouping (e.g. `["infrastructure", "kubernetes"]`). |

---

## 6. Profiles

Set the root-level `profile` field to signal which profile a document follows: `"compact"`, `"full"`, or `"summary"`. Consumers SHOULD accept documents without a `profile` field and infer the profile from content.

### 6.1 Compact profile

For LLM output and low-token pipelines.

**Include:** all required finding fields, `description`, `surfaceId`, `param`, `origin.tool`, `origin.file`, `origin.line`, `trace` (≤5 items), `proofHints.category`, `proofHints.oracle`, `surfaces[].discoveredFrom` when known, `cwe` and `owasp` when known.

**Omit unless known:** `snippet` (keep under 500 chars if included), `payloads` (max 5), `cvss`, `policy`, `investigationHints`, `evidenceSummary`, empty arrays' optional metadata.

**Profile length conventions** (compact vs. schema maximums):

| Field | Compact convention | Schema maximum |
|-------|--------------------|----------------|
| `trace` items | ≤ 5 | 8 |
| `snippet` | ≤ 500 chars | 2000 chars |
| `notes` | ≤ 500 chars | 2000 chars |
| `payloads` | ≤ 5 | 10 |

These are conventions, not enforced by the schema. Compact-profile documents exceeding these limits still validate.

### 6.2 Full profile

For export, audit, and evidence archival. Include all known optional fields.

---

## 7. Code-only findings (no HTTP surface)

Some vulnerabilities within web application codebases are **not reachable via HTTP** (hardcoded secrets, weak crypto, missing certificate validation in code). These are code-only findings that lack an HTTP surface but are still relevant to the application's security posture. This section does **not** apply to non-web targets — VPX is scoped to web applications (see §1.2). These findings:

- MUST include `origin` with at least `origin.tool`.
- SHOULD omit `surfaceId` and `param`.
- SHOULD omit `proofHints` (no runtime proof scheduled).
- SHOULD use `status: "deferred"` or keep `hypothesis` with low `proofPriority`.
- MUST NOT invent a synthetic surface.

Runtime tools skip these unless a separate proof path exists (not defined in VPX 1.0).

---

## 8. Surfaces (extended metadata)

In addition to §4 fields, surfaces MAY include:

| Field | Values | Description |
|-------|--------|-------------|
| `discoveredFrom` | `static`, `runtime`, `openapi`, `inferred` | How the route was determined |
| `routeConfidence` | `verified`, `inferred`, `unknown` | Trust level for executor and SAST consumer |

Executors SHOULD probe `inferred` routes before heavy fuzzing. SAST consumers SHOULD not map `unknown` routes to code without confirmation.

---

## 9. Findings (extended metadata)

Findings MAY include `investigationHints` when runtime discovery lacks source mapping:

```json
{
  "investigationHints": {
    "codeSearchQueries": ["LoginController", "SqlException"],
    "suggestedFiles": ["**/Login*.cs"],
    "notes": "Free-form context for source-analysis LLM"
  }
}
```

| Field | Description |
|-------|-------------|
| `codeSearchQueries` | Terms to search in repository (max 10) |
| `suggestedFiles` | Glob patterns (max 10) |
| `notes` | Short narrative (max 500 chars in compact profile) |

---

## 10. Proofs

A **proof** records one runtime verification attempt.

### 10.1 Proof object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. |
| `findingId` | yes | Links to `findings[].id`. |
| `executedAt` | yes | ISO 8601 UTC timestamp. |
| `tool` | yes | `{ "name": "trowser", "version": "1.0" }` |
| `workflow` | no | Workflow reference (see §10.2). |
| `injection` | no | What was injected (see §10.3). |
| `identity` | no | Session used during proof (see §10.5). |
| `oracle` | no | Outcome check (see §10.4). |
| `evidenceSummary` | no | One-line evidence for LLM handoff (max 500 chars compact). |
| `evidenceBundle` | no | URI or path to replayable artifacts. |
| `elapsedMs` | no | Execution duration. |

### 10.2 Workflow

```json
{
  "type": "verify-workflow",
  "templateId": null,
  "path": "file://evidence/proof-001/workflow.json"
}
```

| `type` | Description |
|--------|-------------|
| `verify-workflow` | Multi-phase setup → trigger → oracle → cleanup. |
| `chain-prove` | Template-driven multi-finding chain proof. |
| `manual` | Ad-hoc test not captured in a workflow file. |

`templateId` accepts `null` or a non-empty string. An empty string `""` is invalid. Use `null` when no template was used.

### 10.3 Injection

```json
{
  "surfaceId": "surf-users-search",
  "param": "q",
  "payload": "' OR '1'='1"
}
```

### 10.4 Oracle

```json
{
  "type": "error",
  "passed": true,
  "evidence": "Response body contains SqlException"
}
```

Use `type` values from [Appendix C — Oracle vocabulary](#appendix-c--oracle-vocabulary). Additional types MAY be used; consumers MUST accept unknown types.

### 10.5 Identity (on proof)

Records the session under which the proof ran:

```json
{ "name": "test-user", "roles": ["user"], "mechanism": "session-cookie" }
```

---

## 11. Verdicts

A **verdict** is the triage outcome for a finding, usually after one or more proofs.

### 11.1 Verdict object

| Field | Required | Description |
|-------|----------|-------------|
| `findingId` | yes | Links to `findings[].id`. |
| `exploitability` | yes | See §11.2. |
| `updatedAt` | no | ISO 8601 UTC. |
| `proofId` | no | Primary proof that determined this verdict. |
| `disposition` | no | Organizational action (§11.3). |
| `justification` | no | Human-readable rationale. |
| `effectiveSeverity` | no | Severity after proof (may differ from static `cvss`). |
| `confidence` | no | 0.0–1.0 confidence in this verdict. |
| `remediation` | no | Fix guidance (§11.4). |
| `rerunToken` | no | Path or ID to re-verify after fix. |

### 11.2 Exploitability

| Value | Meaning |
|-------|---------|
| `confirmed` | Harmful effect demonstrated under test conditions. |
| `not_exploitable` | Tested; vulnerability not reachable or blocked. |
| `inconclusive` | Could not complete test (auth, environment, WAF). |
| `blocked` | Policy or safe mode prevented testing. |
| `deferred` | Not tested; below policy threshold. |
| `hypothesis` | Initial state before any proof attempt. |

Each `findingId` SHOULD have at most one current verdict. Producers MAY append history in a separate document.

### 11.3 Disposition

| Value | Meaning |
|-------|---------|
| `fix-now` | Remediate immediately. |
| `fix-scheduled` | Confirmed or plausible; scheduled fix. |
| `accept-risk` | Documented acceptance (requires `justification`). |
| `false-positive` | Static hypothesis disproven at runtime. |
| `monitor` | Inconclusive; retry later. |

### 11.4 Remediation

Structured feedback for developers or fix LLMs.

```json
{
  "strategy": "parameterized-query",
  "locations": [{ "file": "UserSearchController.cs", "line": 87 }],
  "fixPattern": "Replace string interpolation with SqlParameter",
  "codeHint": "cmd.Parameters.AddWithValue(\"@q\", q);"
}
```

| Field | Description |
|-------|-------------|
| `strategy` | Fix class: `parameterized-query`, `encode-output`, `add-csrf-token`, `authorize-check`, … |
| `locations` | Source locations to change. |
| `fixPattern` | Short prose pattern. |
| `codeHint` | Illustrative fix snippet (not necessarily drop-in). |

---

## 12. Lifecycle

```
┌─────────────┐     proof queued      ┌──────────────────────┐
│  hypothesis │ ────────────────────► │ under_investigation  │
└─────────────┘                       └──────────┬───────────┘
       │                                         │
       │ policy defer                            │ proof executed
       ▼                                         ▼
┌─────────────┐                       ┌──────────────────────┐
│   deferred  │                       │       verdict        │
└─────────────┘                       │ confirmed | not_     │
                                      │ exploitable | ...    │
                                      └──────────┬───────────┘
                                                 │
                                                 ▼ fix + rerun
                                      ┌──────────────────────┐
                                      │  not_exploitable or  │
                                      │  false-positive      │
                                      └──────────────────────┘
```

1. Producer creates `findings[]` with `status: "hypothesis"`.
2. Executor runs proofs; appends `proofs[]`.
3. Executor or triage tool writes `verdicts[]`.
4. Fix agent consumes `verdicts[].remediation`.
5. After fix, executor re-runs proof; updates verdict and `rerunToken`.

---

## 13. Document composition

VPX documents are **merged**, not forked, when static and runtime producers collaborate.

### 13.1 Single document rule

One triage record SHOULD share one `documentId` across the pipeline. Producers append sections; they do not replace unrelated findings.

### 13.2 Merge algorithm

Given **Base** (typically static SAST output) and **Update** (typically runtime proof output):

1. Start from Base copy.
2. **Surfaces:** union by `(route, method)`; prefer Update entry when `routeConfidence` is higher (`verified` > `inferred` > `unknown`).
3. **Findings:** union by `id`; if conflict, keep Base finding text, append Update `investigationHints` only if Base lacks `origin.file`.
4. **Proofs:** append all from Update; never remove proofs.
5. **Verdicts:** for each `findingId`, keep Update verdict if present (latest `updatedAt` wins).
6. Set `updatedAt` to merge timestamp.

### 13.3 Matching when IDs differ

If Update proof references unknown `findingId`, match Update finding to Base by:

1. `(surfaceId, param, kind)`
2. `(route, method, param, kind)` via surface resolution
3. If no match, append as new finding (runtime-only discovery)

### 13.4 Producer responsibilities

| Producer | Writes | Must preserve |
|----------|--------|---------------|
| Static SAST | `findings`, `surfaces`, `target` | Stable `finding.id` |
| Runtime tester | `proofs`, `verdicts` | Inbound `finding.id` |
| SAST consumer | revised `findings`, new `verdicts` | Proof history |

### 13.5 Four-perspective guides

| Perspective | Guide |
|-------------|-------|
| Static analysis → outbound | [LLM Author Guide](../guides/LLM-AUTHOR-GUIDE.md) |
| Static analysis ← inbound | [SAST Consumer Guide](../guides/SAST-CONSUMER-GUIDE.md) |
| Black-box → outbound | [Runtime Author Guide](../guides/RUNTIME-AUTHOR-GUIDE.md) |
| Black-box ← inbound | [Runtime Author Guide](../guides/RUNTIME-AUTHOR-GUIDE.md) § Pattern A, [Implementer Guide](../guides/IMPLEMENTER-GUIDE.md) |

---

## 14. Identifiers and references

- **`documentId`**: UUID v4 recommended.
- **`surfaces[].id`**, **`findings[].id`**, **`proofs[].id`**: unique within the document; stable for the life of the triage record.
- **Cross-references**: `findings[].surfaceId` → `surfaces[].id`; `proofs[].findingId` → `findings[].id`; `verdicts[].findingId` → `findings[].id`; `verdicts[].proofId` → `proofs[].id`.

---

## 15. Security considerations

- VPX documents MAY contain sensitive data: URLs, payloads, code snippets, session hints.
- Producers SHOULD redact secrets from `snippet`, `payload`, and `evidence`.
- `evidenceBundle` paths MAY contain screenshots and network captures — treat as confidential.
- Executors MUST NOT exfiltrate proof results to third parties without explicit authorization.

---

## 16. IANA considerations

None. VPX is a media type convention, not an IANA registration at v1.0.

Suggested unofficial media type: `application/vnd.vpx+json`

---

## Appendix A — Minimal valid document

```json
{
  "vpxVersion": "1.0",
  "documentId": "550e8400-e29b-41d4-a716-446655440000",
  "target": { "baseUrl": "https://app.example.com" },
  "surfaces": [],
  "findings": [],
  "proofs": [],
  "verdicts": []
}
```

## Appendix B — Normative schema

The JSON Schema at [`../schema/vpx-1.0.schema.json`](../schema/vpx-1.0.schema.json) is normative for field types and required properties. If this document and the schema disagree, the schema governs structure; this document governs semantics.

## Appendix C — Oracle vocabulary

Recommended `oracle.type` and `proofHints.oracle` values. Consumers MUST accept values not listed here.

| Type | Signal | Typical kinds |
|------|--------|---------------|
| `error` | Error page, stack trace, SQL message | sqli, deserialization |
| `timing` | Measurable response delay | sqli (blind), ssti |
| `reflection` | Payload echoed in response body | xss, ssti |
| `dom-change` | DOM or visible UI change in browser | xss, csrf |
| `status-code` | Unexpected HTTP status or redirect | idor, open-redirect, csrf |
| `network-match` | Body/header pattern without full reflection | ssrf, info-leak |
| `data-change` | Persistent side-effect observed (e.g. record in database, file created) | csrf, mass-assignment, idor |
| `error-or-timing` | Either error or timing (executor chooses) | sqli |
| `none` | No oracle configured | — |

Composite hints (`error-or-timing`) are valid in `proofHints.oracle`; proofs SHOULD record the actual signal in `proofs[].oracle.type`.
