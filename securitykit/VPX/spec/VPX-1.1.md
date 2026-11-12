# VPX 1.1 — Vulnerability Proof eXchange

**Status:** Published  
**Version:** 1.1  
**Date:** 2026-08-28  
**Schema:** [`../schema/vpx-1.1.schema.json`](../schema/vpx-1.1.schema.json)  
**Supersedes:** [VPX 1.0](./VPX-1.0.md)

---

## 1. Introduction

### 1.1 Purpose

VPX (Vulnerability Proof eXchange) is a JSON document format for exchanging information between independent actors that may:

1. Analyze source code and report vulnerability hypotheses.
2. Attempt to reproduce or exploit those hypotheses.
3. Review the evidence and issue a final verdict.

An actor can be an LLM, a conventional analysis tool, a runtime testing tool, or a human. VPX preserves each actor's contribution rather than replacing it with a merged summary.

The central lifecycle is:

```text
hypothesis -> proof attempts -> adjudicated verdict -> remediation -> rerun
```

VPX documents **what is needed to prioritize, prove, and remediate** application vulnerabilities — and nothing more. It does not define how an LLM is prompted, how consensus is calculated, or which actor is authorized to approve a verdict.

### 1.2 Scope

VPX targets **web application vulnerabilities** — issues reachable or discoverable through HTTP surfaces, web APIs, and their supporting server-side code. Surfaces are modeled as HTTP endpoints (route + method); findings bind to those surfaces or to source-code locations within web application codebases.

VPX is not designed for native-binary, mobile, embedded, or desktop-application vulnerability analysis. Producers SHOULD verify the target is a web application before emitting VPX output.

VPX does **not** define:

- Software bill of materials or dependency CVE inventory
- Generic static-analysis rule catalogs
- Transport protocols or API endpoints (implementers choose)
- Prompt text, consensus algorithms, or approval policy

### 1.3 Design principles

1. **Preserve observations.** Do not discard disagreement or unsuccessful proof attempts.
2. **Separate evidence from decisions.** A proof records what happened; a verdict records what the organization concludes.
3. **Make every contribution attributable.** Findings, proofs, assessments, and verdicts identify the run that produced them.
4. **Bind conclusions to immutable targets.** Source findings identify a source revision, and runtime proofs identify the deployed build and environment.
5. **Treat negative test results cautiously.** Failure to reproduce is not, by itself, proof that a vulnerability is impossible to exploit.
6. **Remain compact.** Large or sensitive evidence stays in external artifacts.
7. **Be forward compatible.** Consumers ignore and preserve unknown properties.

### 1.4 Design heuristic

> **Document what is needed, but not more than that.**

Every field in VPX must earn its place by enabling hypothesis → proof → verdict → fix. Optional fields exist only when they reduce ambiguity for the next actor in the pipeline.

### 1.5 Conformance

A VPX 1.1 document **MUST**:

1. Be UTF-8 JSON.
2. Include `vpxVersion` matching `^1\.[1-9][0-9]*$` (for example `"1.1"`). New 1.1 producers MUST emit `"1.1"`.
3. Include a unique `documentId` (UUID recommended).
4. Include all seven top-level arrays: `runs`, `surfaces`, `findings`, `assessments`, `proofs`, `artifacts`, `verdicts` (each MAY be empty).
5. Validate against the normative JSON Schema unless explicitly using a documented profile subset.
6. Satisfy referential integrity for all `*Id` and `*Ids` fields (see §18).

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Hypothesis** | A reported vulnerability that has not yet been proven or disproven at runtime. |
| **Surface** | An HTTP-accessible entry point: route, method, parameters, and auth context. |
| **Run** | One bounded execution by one actor (analysis, proof, aggregation, adjudication, fix, or rerun). |
| **Assessment** | An actor's independent interpretation of a finding or proof. |
| **Proof** | A recorded attempt to verify exploitability under realistic session conditions. |
| **Artifact** | Metadata and integrity information for evidence stored outside the VPX document. |
| **Verdict** | Adjudicated triage outcome: exploitability status, disposition, and optional remediation hints. |
| **Producer** | Tool or agent that creates or updates VPX documents. |
| **Executor** | Tool that runs proofs against a live target. |
| **Consumer** | Tool or agent that reads a VPX document. |

---

## 3. Compatibility and unknown properties

### 3.1 Schema policy

The conformance schema uses `"additionalProperties": true` on the root object and on objects intended to evolve, including `target`, `run`, `actor`, `surface`, `finding`, `assessment`, `proof`, `oracle`, `artifact`, `verdict`, and `remediation`.

VPX separates two concerns:

- **Conformance validation:** required fields, types, ranges, and known semantics, while allowing unknown properties.
- **Strict linting:** warns about unknown unnamespaced properties and likely misspellings. A lint warning MUST NOT make an otherwise conforming document unreadable.

The strict linter is [`../tools/vpx-lint.ps1`](../tools/vpx-lint.ps1).

### 3.2 Consumer requirements

A conforming consumer:

1. MUST ignore unknown properties when interpreting a document.
2. SHOULD preserve unknown properties when reading and writing the same record.
3. MUST NOT let an unknown property override the meaning of a standard field.
4. MUST NOT treat an extension as security-authoritative unless configured to understand that extension.

### 3.3 Extension naming

Experimental and vendor-specific properties SHOULD use an `x-` prefix followed by an organization or project name:

```json
{
  "x-acme-modelRiskScore": 73,
  "x-trowser-browserContext": "ctx-17"
}
```

Unprefixed names are reserved for present or future VPX standard fields.

### 3.4 Version handling

Consumers SHOULD accept later minor versions with the same major version:

```text
consumer 1.1 -> accepts 1.1, 1.2, 1.3, ...
consumer 1.1 -> rejects 2.0 unless explicitly supported
```

Consumers MUST use fields only according to semantics they understand.

A 1.1 consumer MUST accept VPX 1.0 documents for import. See §20 for downgrade from 1.1 to 1.0.

---

## 4. Document model

### 4.1 Root object

| Field | Required | Description |
|-------|----------|-------------|
| `vpxVersion` | yes | Format version. New producers MUST emit `"1.1"`. |
| `documentId` | yes | Stable identifier for this document instance. |
| `createdAt` | no | ISO 8601 UTC timestamp of first creation. |
| `updatedAt` | no | ISO 8601 UTC timestamp of last modification. |
| `profile` | no | Profile in use: `compact`, `full`, or `summary`. |
| `target` | no | Deployment under test. |
| `policy` | no | Organizational triage rules. |
| `runs` | yes | Provenance for analysis, proof, aggregation, and adjudication. May be `[]`. |
| `surfaces` | yes | Attack surface catalog. May be `[]`. |
| `findings` | yes | Vulnerability hypotheses. May be `[]`. |
| `assessments` | yes | Independent opinions about a finding or proof. May be `[]`. |
| `proofs` | yes | Proof execution records. May be `[]`. |
| `artifacts` | yes | External evidence metadata. May be `[]`. |
| `verdicts` | yes | Triage outcomes. May be `[]`. |

```json
{
  "vpxVersion": "1.1",
  "documentId": "550e8400-e29b-41d4-a716-446655440000",
  "target": {},
  "runs": [],
  "surfaces": [],
  "findings": [],
  "assessments": [],
  "proofs": [],
  "artifacts": [],
  "verdicts": []
}
```

### 4.2 Target

Describes the application instance proofs apply to. Source and runtime conclusions SHOULD be tied to the exact software tested.

```json
{
  "repository": "https://github.com/acme/webapp",
  "commit": "abc123def456",
  "sourceDigest": {
    "algorithm": "sha-256",
    "value": "..."
  },
  "baseUrl": "https://staging.example.com",
  "environment": "staging",
  "deploymentId": "deploy-2026-08-26-17",
  "buildDigest": {
    "algorithm": "sha-256",
    "value": "..."
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `baseUrl` | no | Origin URL for relative routes in surfaces. |
| `repository` | no | Source repository URI or path. |
| `commit` | no | Immutable commit identifier. SHOULD NOT be a branch or tag. |
| `environment` | no | Free-form: `production`, `staging`, `local`, etc. |
| `deploymentId` | no | Identifier for the deployed instance under test. |
| `sourceDigest` | no | Digest of the analyzed source tree. |
| `buildDigest` | no | Digest of the deployed build. |

A runtime proof SHOULD include `deploymentId` or `buildDigest` on the proof `targetSnapshot` when available.

### 4.3 Policy

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

## 5. Runs and actor provenance

A run describes one bounded execution by one actor.

### 5.1 Run object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Stable identifier within the document |
| `stage` | yes | `source-analysis`, `proof`, `aggregation`, `adjudication`, `fix`, or `rerun` |
| `actor` | yes | Actor responsible for the run |
| `startedAt` | no | ISO 8601 UTC timestamp |
| `completedAt` | no | ISO 8601 UTC timestamp |
| `inputArtifactIds` | no | Artifacts consumed by the run |
| `outputArtifactIds` | no | Artifacts produced by the run |
| `configuration` | no | Reproducibility metadata without embedded secrets |

```json
{
  "id": "run-source-model-a",
  "stage": "source-analysis",
  "actor": {
    "type": "llm",
    "name": "model-a",
    "version": "2026-08-15",
    "provider": "example-provider"
  },
  "startedAt": "2026-08-26T08:00:00Z",
  "completedAt": "2026-08-26T08:07:31Z",
  "inputArtifactIds": ["artifact-source-manifest"],
  "configuration": {
    "promptTemplateDigest": {
      "algorithm": "sha-256",
      "value": "..."
    },
    "temperature": 0.1
  }
}
```

### 5.2 Actor object

| Field | Required | Description |
|-------|----------|-------------|
| `type` | yes | `llm`, `tool`, `human`, or `service` |
| `name` | yes | Model, tool, person role, or service name |
| `version` | no | Model checkpoint or tool version |
| `provider` | no | Provider or organization |

Human actors SHOULD be represented by a role or organization-local identifier. VPX documents SHOULD avoid unnecessary personal information.

Model configuration MAY include sampling parameters and hashes of system prompts or prompt templates. Documents SHOULD NOT contain confidential prompts, API keys, credentials, or provider request identifiers that disclose secrets.

---

## 6. Surfaces

A **surface** is a deduplicated runtime entry point. Multiple findings MAY reference the same `surfaceId`.

### 6.1 Surface object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. Recommended: short slug (`surf-users-search`). |
| `route` | yes | Path (`/api/users`) or absolute URL. |
| `method` | yes | HTTP method (`GET`, `POST`, …). |
| `params` | no | Input parameters (see §6.2). |
| `auth` | no | Authentication context (see §6.3). |
| `discoveredFrom` | no | `static`, `runtime`, `openapi`, or `inferred`. |
| `routeConfidence` | no | `verified`, `inferred`, or `unknown`. |

Executors SHOULD probe `inferred` routes before heavy fuzzing. SAST consumers SHOULD not map `unknown` routes to code without confirmation.

### 6.2 Parameter

```json
{ "name": "q", "in": "query", "type": "string" }
```

| Field | Required | Values |
|-------|----------|--------|
| `name` | yes | Parameter name. |
| `in` | yes | `query`, `body`, `path`, `header`, `cookie` |
| `type` | no | `string`, `number`, `boolean`, `object`, `array` |

### 6.3 Auth

```json
{ "required": true, "roles": ["user"], "mechanism": "session-cookie" }
```

| Field | Description |
|-------|-------------|
| `required` | Whether authentication is needed to reach the surface. |
| `roles` | Roles or scopes that can access the surface. |
| `mechanism` | Free-form: `session-cookie`, `bearer-jwt`, `api-key`, `none`, etc. |

---

## 7. Findings

A **finding** is a vulnerability hypothesis.

### 7.1 Required fields

| Field | Description |
|-------|-------------|
| `id` | Unique within document. Canonical identifier for this record. |
| `kind` | Vulnerability category (see §7.6). |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `title` | Short human-readable summary. |
| `status` | Lifecycle state (see §7.7). |

`description` is optional but recommended (max 2000 chars). It separates "what this is" from `investigationHints` "how to investigate".

### 7.2 Stable finding fingerprint

`findings[].id` remains the canonical identifier within one VPX document. `fingerprint` correlates equivalent reports across documents and independent model runs.

```json
{
  "id": "finding-sqli-user-search",
  "fingerprint": {
    "algorithm": "vpx-fingerprint-1",
    "value": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

The exact canonicalization is defined in [Appendix D](#appendix-d--vpx-fingerprint-1-canonicalization). Producers MUST NOT use an LLM-generated title or description as the sole fingerprint input.

### 7.3 Surface binding

| Field | Description |
|-------|-------------|
| `surfaceId` | Reference to `surfaces[].id`. |
| `surfaceIds` | Array of additional surface IDs when a finding spans multiple surfaces. |
| `param` | Parameter name on that surface implicated in the vulnerability. |

At least one of `surfaceId` or `origin` SHOULD be present. Both MAY be present.

### 7.4 Origin (static context)

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

### 7.5 Trace

`trace` is an ordered array of short strings describing data or control flow. **Maximum 8 entries** in full profile; **5 in compact**.

### 7.6 Kind (category)

Use lowercase kebab-case. Common values:

`sqli`, `xss`, `csrf`, `idor`, `ssrf`, `open-redirect`, `path-traversal`, `mass-assignment`, `ssti`, `command-injection`, `deserialization`, `header-injection`, `auth-bypass`, `info-leak`, `misconfiguration`, `other`

Producers MAY emit additional kinds; consumers MUST accept unknown kinds without failing.

### 7.7 Status (finding lifecycle)

| Value | Meaning |
|-------|---------|
| `hypothesis` | Reported, not yet tested at runtime. |
| `under_investigation` | Proof queued or in progress. |
| `deferred` | Below policy threshold; proof not scheduled. |

After proof, update via `verdicts[]` — do not overload `findings[].status` with exploitability outcomes.

### 7.8 Source provenance

```json
{
  "reportedByRunIds": ["run-source-model-a", "run-source-model-b"],
  "assessmentIds": ["assessment-a", "assessment-b", "assessment-c"]
}
```

An aggregation run MAY create the canonical finding after clustering reports from several source-analysis runs. Aggregation MUST NOT erase the individual assessments.

### 7.9 Proof hints

Hints for executors. Omit fields unknown to the producer.

| Field | Description |
|-------|-------------|
| `category` | Normalized scanner category (often matches `kind`). |
| `payloads` | Suggested injection strings (max 5 in compact). |
| `oracle` | Expected signal: `error`, `timing`, `reflection`, `dom-change`, `status-code`, `network-match`, `data-change`, etc. |
| `identity` | Session needed: `anonymous`, `authenticated-user`, `admin`, or named identity. |

### 7.10 Scoring, classification, and relationships

| Field | Range / type | Description |
|-------|--------------|-------------|
| `cvss` | 0.0–10.0 | Theoretical severity from static analysis. |
| `confidence` | 0.0–1.0 | Producer confidence in this hypothesis. Distinct from `verdicts[].confidence` and `assessments[].confidence`. |
| `proofPriority` | 0–100 | Suggested proof queue priority (higher = prove first). |
| `owasp` | string | OWASP category identifier (e.g. `A05`). |
| `cwe` | string[] | CWE identifiers (e.g. `["CWE-89"]`). Keep `origin.rule` for scanner-specific rule IDs. |
| `reference` | string | URL or external reference identifier. |
| `remediation` | string | Short prose remediation (max 2000 chars). Structured fix data belongs on `verdicts[].remediation`. |
| `relatedFindingIds` | string[] | Findings that interact with this one. |
| `tags` | string[] | Free-form labels. |
| `investigationHints` | object | Runtime-to-static handoff when `origin.file` is unknown. |

---

## 8. Assessments

An assessment is an actor's independent interpretation of a finding or proof. It preserves agreement, disagreement, uncertainty, rationale, and confidence.

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique assessment identifier |
| `findingId` | yes | Finding being assessed |
| `runId` | yes | Run that produced the assessment |
| `phase` | yes | `source-analysis`, `proof-review`, or `adjudication` |
| `conclusion` | yes | `supports`, `disputes`, or `inconclusive` |
| `rationale` | yes | Concise explanation |
| `proofId` | no | Proof being reviewed (when `phase` is `proof-review`) |
| `confidence` | no | Actor confidence from 0.0 through 1.0 |
| `locations` | no | Actor-specific source locations |
| `trace` | no | Actor-specific data or control-flow trace |
| `artifactIds` | no | Supporting or counter-evidence |

Confidence values from different models MUST NOT be assumed to be calibrated or directly comparable. A consensus process MAY use them, but MUST record its own method and output as a separate aggregation run.

---

## 9. Proofs

A **proof** records one runtime verification attempt. Every attempt is a separate `proofs[]` entry. Attempts MUST NOT be overwritten, including unsuccessful, blocked, or erroneous attempts.

### 9.1 Proof object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. |
| `findingId` | yes | Links to `findings[].id`. |
| `runId` | yes | Run that executed this attempt. |
| `executedAt` | yes | ISO 8601 UTC timestamp. |
| `outcome` | yes | Explicit result (see §9.2). |
| `tool` | no | `{ "name": "trowser", "version": "1.1" }` — convenience copy of the run actor. |
| `workflow` | no | Workflow reference (see §9.4). |
| `injection` | no | What was injected. |
| `identity` | no | Session used during proof. |
| `oracle` | no | Outcome check (see §9.3). |
| `targetSnapshot` | no | Deployment identity at execution time. |
| `preconditions` | no | Conditions assumed before the attempt. |
| `limitations` | no | Material gaps (especially for `not-reproduced`). |
| `cleanup` | no | `{ "status": "completed" \| "not-required" \| "failed" \| "unknown" }` |
| `artifactIds` | no | External evidence for this attempt. |
| `evidenceSummary` | no | One-line evidence for LLM handoff (max 500 chars compact). |
| `evidenceBundle` | no | **Deprecated.** Prefer `artifactIds`. |
| `elapsedMs` | no | Execution duration. |

`limitations` is important for interpreting `not-reproduced`. A proof executor SHOULD describe material gaps such as unavailable credentials, untested payload classes, rate limiting, WAF interference, missing seed data, or incomplete workflow coverage.

### 9.2 Explicit outcome

| Outcome | Meaning |
|---------|---------|
| `exploited` | The defined harmful effect was demonstrated |
| `not-reproduced` | The attempt completed but did not demonstrate the effect |
| `blocked` | Policy, safety controls, authorization, or environment prevented the attempt |
| `error` | Tooling or execution failed |
| `inconclusive` | Evidence was insufficient to classify the result |

A `not-reproduced` proof MUST NOT automatically produce a `not_exploitable` verdict.

### 9.3 Oracle

`oracle.passed` is deprecated because “passed” can ambiguously mean either “the security control passed” or “the exploit succeeded.” Producers SHOULD instead record:

```json
{
  "outcome": "exploited",
  "oracle": {
    "type": "data-change",
    "observed": true,
    "expectedSignal": "A record owned by another user is returned",
    "actualSignal": "Response contained record account-7821"
  }
}
```

| Field | Description |
|-------|-------------|
| `type` | Signal class from [Appendix C](#appendix-c--oracle-vocabulary). |
| `observed` | Whether the expected harmful-effect signal was observed. |
| `expectedSignal` | What the executor looked for. |
| `actualSignal` | What was actually seen. |
| `passed` | **Deprecated.** Consumers MAY still read it from VPX 1.0 documents. |
| `evidence` | Legacy string or object. Prefer `actualSignal`. |

If both `observed` and deprecated `passed` are present, `observed` is authoritative.

### 9.4 Workflow

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

`templateId` accepts `null` or a non-empty string. An empty string `""` is invalid.

---

## 10. Evidence artifacts

Large evidence is stored outside the VPX document and referenced through `artifacts[]`.

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. |
| `kind` | yes | Artifact class. |
| `uri` | no | Locator for the stored bytes. |
| `mediaType` | no | MIME type. |
| `digest` | no | Integrity digest. Consumers MUST verify it before relying on external evidence when present. |
| `size` | no | Size in bytes. |
| `createdAt` | no | ISO 8601 UTC. |
| `sensitivity` | no | `public`, `internal`, `confidential`, or `secret`. |
| `redaction` | no | `{ "status": "none" \| "redacted" \| "unknown", "description": "..." }` |
| `producedByRunId` | no | Run that created the artifact. |

Recommended `kind` values: `source-manifest`, `model-output`, `code-excerpt`, `http-transcript`, `browser-recording`, `screenshot`, `proof-script`, `workflow`, `tool-log`, `human-note`.

Producers MUST redact credentials, session tokens, API keys, and unrelated personal data. Access control and retention policy apply to both the VPX document and referenced artifacts.

---

## 11. Verdicts and adjudication

A **verdict** is the triage outcome for a finding, usually after one or more proofs and assessments. Verdicts are append-only. A new verdict supersedes an older verdict explicitly via `supersedesVerdictId`.

Consumers determine the current verdict by following `supersedesVerdictId`. They MUST NOT silently choose a verdict solely by array order or timestamp.

### 11.1 Verdict object

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique within document. |
| `findingId` | yes | Links to `findings[].id`. |
| `exploitability` | yes | See §11.2. |
| `runId` | no | Adjudication run. |
| `supersedesVerdictId` | no | Previous verdict this record replaces. |
| `basedOnAssessmentIds` | no | Assessments considered. |
| `basedOnProofIds` | no | Proofs considered. |
| `proofId` | no | **Deprecated.** Consumers MAY read it from VPX 1.0 documents. |
| `updatedAt` | no | ISO 8601 UTC. |
| `disposition` | no | Organizational action (§11.3). |
| `justification` | no | Human-readable rationale. |
| `effectiveSeverity` | no | Severity after proof. |
| `confidence` | no | 0.0–1.0 confidence in this verdict. |
| `remediation` | no | Fix guidance (§11.4). |
| `approval` | no | `{ "status": "approved" \| "rejected" \| "pending", "approvedByRunId": "..." }` |
| `rerunToken` | no | Path or ID to re-verify after fix. |

If both `basedOnProofIds` and deprecated `proofId` are present, `basedOnProofIds` is authoritative. If only `proofId` is present, treat it as `basedOnProofIds: [<proofId>]`.

### 11.2 Exploitability

| Value | Meaning |
|-------|---------|
| `confirmed` | A harmful effect was demonstrated and accepted by adjudication |
| `not_exploitable` | Evidence establishes that exploitation is prevented for the identified target and conditions |
| `not_reproduced` | Proof attempts did not demonstrate exploitation, but impossibility was not established |
| `inconclusive` | Available evidence does not support a conclusion |
| `blocked` | Testing was prevented by policy, authorization, safety, or environment |
| `deferred` | Testing was intentionally postponed |
| `hypothesis` | No adjudicated exploitability conclusion exists |

A `false-positive` disposition SHOULD require reasoning about the source hypothesis, not merely a failed runtime test. For example: the alleged source-to-sink path does not exist; the value is encoded or parameterized before reaching the sink; the code is unreachable in the identified build; or the report refers to the wrong route, parameter, or component.

### 11.3 Disposition

| Value | Meaning |
|-------|---------|
| `fix-now` | Remediate immediately. |
| `fix-scheduled` | Confirmed or plausible; scheduled fix. |
| `accept-risk` | Documented acceptance (requires `justification`). |
| `false-positive` | Static hypothesis disproven — not merely unreproduced. |
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

---

## 12. Profiles

Set the root-level `profile` field to signal which profile a document follows: `"compact"`, `"full"`, or `"summary"`. Consumers SHOULD accept documents without a `profile` field and infer the profile from content.

### 12.1 Compact profile

For LLM output and low-token pipelines.

**Include:** all required finding fields, `description`, `surfaceId`, `param`, `origin.tool`, `origin.file`, `origin.line`, `trace` (≤5 items), `proofHints.category`, `proofHints.oracle`, `cwe` and `owasp` when known, `fingerprint` when computable, `reportedByRunIds` when a run exists, proof `outcome` and `runId`, verdict `id`.

**Omit unless known:** `snippet` (keep under 500 chars if included), `payloads` (max 5), `cvss`, `policy`, `investigationHints`, `evidenceSummary`, artifact bodies, run `configuration` details, empty optional metadata.

**Profile length conventions** (compact vs. schema maximums):

| Field | Compact convention | Schema maximum |
|-------|--------------------|----------------|
| `trace` items | ≤ 5 | 8 |
| `snippet` | ≤ 500 chars | 2000 chars |
| `notes` | ≤ 500 chars | 2000 chars |
| `payloads` | ≤ 5 | 10 |
| `rationale` | ≤ 500 chars | unbounded |

These are conventions, not enforced by the schema.

### 12.2 Full profile

For export, audit, and evidence archival. Include all known optional fields, including assessments, artifacts with digests, proof `limitations`, `targetSnapshot`, and verdict provenance (`basedOnAssessmentIds`, `basedOnProofIds`, `runId`).

### 12.3 Summary profile

Non-normative condensed view for LLM first-call triage. MAY omit proofs, assessments, and artifacts. MUST still declare `vpxVersion`. Summary documents are not a substitute for the canonical record.

---

## 13. Code-only findings (no HTTP surface)

Some vulnerabilities within web application codebases are **not reachable via HTTP** (hardcoded secrets, weak crypto, missing certificate validation in code). These findings:

- MUST include `origin` with at least `origin.tool`.
- SHOULD omit `surfaceId` and `param`.
- SHOULD omit `proofHints` (no runtime proof scheduled).
- SHOULD use `status: "deferred"` or keep `hypothesis` with low `proofPriority`.
- MUST NOT invent a synthetic surface.

Runtime tools skip these unless a separate proof path exists.

---

## 14. Lifecycle

```
┌─────────────┐     proof queued      ┌──────────────────────┐
│  hypothesis │ ────────────────────► │ under_investigation  │
└─────────────┘                       └──────────┬───────────┘
       │                                         │
       │ policy defer                            │ proof executed
       ▼                                         ▼
┌─────────────┐                       ┌──────────────────────┐
│   deferred  │                       │  proofs[] + optional │
└─────────────┘                       │  assessments[]       │
                                      └──────────┬───────────┘
                                                 │ adjudication run
                                                 ▼
                                      ┌──────────────────────┐
                                      │       verdict        │
                                      │ confirmed | not_     │
                                      │ reproduced | ...     │
                                      └──────────┬───────────┘
                                                 │
                                                 ▼ fix + rerun
                                      ┌──────────────────────┐
                                      │  new verdict         │
                                      │  supersedes prior    │
                                      └──────────────────────┘
```

1. Producer creates `runs[]` and `findings[]` with `status: "hypothesis"`, plus `assessments[]`.
2. Executor appends `proofs[]` (never overwrites) and optional proof-review assessments.
3. An adjudication run writes `verdicts[]` referencing the material assessments and proofs.
4. Fix agent consumes `verdicts[].remediation`.
5. After fix, executor re-runs proof; a new verdict sets `supersedesVerdictId`.

---

## 15. Document composition

VPX documents are **merged**, not forked, when independent producers collaborate. VPX 1.0's “latest update wins” rule for verdicts is replaced.

### 15.1 Single document rule

One triage record SHOULD share one `documentId` across the pipeline. Producers append sections; they do not replace unrelated findings.

### 15.2 Merge algorithm

Given **Base** and **Update**:

1. **Runs:** union by `id`; conflicting content is a merge error.
2. **Surfaces:** union by stable ID or normalized `(route, method)`. Preserve provenance when selecting canonical metadata. Prefer higher `routeConfidence` (`verified` > `inferred` > `unknown`).
3. **Findings:** union by `id`; otherwise correlate by fingerprint. Conflicting fingerprints for the same ID are a merge error.
4. **Assessments:** append and deduplicate by `id`; never replace an assessment.
5. **Proofs:** append and deduplicate by `id`; never replace a proof.
6. **Artifacts:** union by `id`; a digest conflict is a merge error.
7. **Verdicts:** append and deduplicate by `id`; use `supersedesVerdictId` to establish history.
8. **Unknown properties:** preserve them where technically possible.
9. Set `updatedAt` to the merge timestamp.

Automatic correlation MUST be recorded as an aggregation run. Ambiguous matches require human review and MUST NOT be silently merged.

### 15.3 Matching when IDs differ

If Update proof references unknown `findingId`, match Update finding to Base by:

1. Exact `findings[].id`
2. Matching `fingerprint.value` under `vpx-fingerprint-1`
3. `(surfaceId, param, kind)`
4. `(route, method, param, kind)` via surface resolution

If no match, append as a new finding (runtime-only discovery). Fuzzy title matching MAY be offered for human review; it MUST NOT auto-merge.

### 15.4 Producer responsibilities

| Producer | Writes | Must preserve |
|----------|--------|---------------|
| Static SAST | `findings`, `surfaces`, `target`, `runs`, `assessments` | Stable `finding.id` and assessments |
| Runtime tester | `proofs`, `runs`, `artifacts`, optional `verdicts` | Inbound `finding.id` and prior proofs |
| Adjudicator | `verdicts`, adjudication `runs` | Proof and assessment history |
| SAST consumer | revised `findings`, new `verdicts` | Proof and assessment history |

### 15.5 Multi-model workflow

For several source-analysis models and several proof models:

1. Create one `run` per source-analysis model.
2. Keep each model's assessment independent.
3. Cluster equivalent reports using fingerprints plus deterministic matching.
4. Create or update a canonical finding without deleting source assessments.
5. Let a human accept, reject, split, or merge candidate clusters.
6. Create one `run` per proof model.
7. Append every proof attempt with its outcome, limitations, and artifacts.
8. Record each proof model's interpretation as an assessment when useful.
9. Create a distinct adjudication run.
10. Issue a verdict referencing all material assessments and proofs.

Model majority is evidence, not ground truth. Two models repeating the same unsupported assumption do not outweigh one model with replayable contrary evidence.

---

## 16. SARIF interoperability

VPX remains the canonical hypothesis-to-proof record. SARIF 2.1 remains the recommended interchange format for code-scanning platforms and IDEs.

### 16.1 SARIF to VPX

| SARIF | VPX |
|-------|-----|
| `run` | `run` |
| `result` | `finding` plus source `assessment` |
| `ruleId` and taxonomy | `origin.rule`, `cwe`, `owasp` |
| `locations` | `origin` and assessment `locations` |
| `codeFlows` | assessment `trace` |
| `partialFingerprints` | `fingerprint` |
| result `properties` | namespaced VPX extension properties |

### 16.2 VPX to SARIF

Export canonical findings as SARIF results. Preserve the VPX finding ID and fingerprint in SARIF properties or partial fingerprints. Runtime proof details MAY be summarized in SARIF properties, but the VPX document remains authoritative because SARIF has no standard representation for the complete proof and verdict history.

---

## 17. Signing and integrity

VPX 1.1 defines artifact digests but does not define an embedded signature format. Deployments requiring tamper evidence SHOULD sign the complete VPX document using an external envelope such as DSSE/in-toto and SHOULD bind the signature to:

- the VPX document digest;
- the source revision;
- the deployment or build digest; and
- externally stored evidence artifact digests.

Signature verification failure MUST be surfaced and MUST NOT be converted into an ordinary inconclusive proof outcome.

---

## 18. Identifiers and referential integrity

- **`documentId`**: UUID v4 recommended.
- **`runs[].id`**, **`surfaces[].id`**, **`findings[].id`**, **`assessments[].id`**, **`proofs[].id`**, **`artifacts[].id`**, **`verdicts[].id`**: unique within the document; stable for the life of the triage record.

Cross-references that MUST resolve when present:

| Field | Must exist in |
|-------|----------------|
| `findings[].surfaceId` / `surfaceIds[]` | `surfaces[].id` |
| `findings[].relatedFindingIds[]` | `findings[].id` |
| `findings[].reportedByRunIds[]` | `runs[].id` |
| `findings[].assessmentIds[]` | `assessments[].id` |
| `assessments[].findingId` | `findings[].id` |
| `assessments[].runId` | `runs[].id` |
| `assessments[].proofId` | `proofs[].id` |
| `assessments[].artifactIds[]` | `artifacts[].id` |
| `proofs[].findingId` | `findings[].id` |
| `proofs[].runId` | `runs[].id` |
| `proofs[].artifactIds[]` | `artifacts[].id` |
| `proofs[].injection.surfaceId` | `surfaces[].id` |
| `artifacts[].producedByRunId` | `runs[].id` |
| `runs[].inputArtifactIds[]` / `outputArtifactIds[]` | `artifacts[].id` |
| `verdicts[].findingId` | `findings[].id` |
| `verdicts[].runId` | `runs[].id` |
| `verdicts[].basedOnAssessmentIds[]` | `assessments[].id` |
| `verdicts[].basedOnProofIds[]` / `proofId` | `proofs[].id` |
| `verdicts[].supersedesVerdictId` | `verdicts[].id` |
| `verdicts[].approval.approvedByRunId` | `runs[].id` |

A dangling reference is a conformance error. The linter reports these as errors, not warnings.

---

## 19. Security considerations

- VPX documents and artifacts MAY contain exploit payloads, application data, and security-sensitive implementation details.
- Producers MUST redact credentials, session tokens, API keys, and unrelated personal data from snippets, payloads, and evidence.
- `artifacts[].uri` paths MAY contain screenshots and network captures — treat according to `sensitivity`.
- Executors MUST NOT exfiltrate proof results to third parties without explicit authorization.
- Unknown extension properties MUST NOT be treated as security-authoritative unless the consumer is configured to understand them.

---

## 20. Downgrade from VPX 1.1 to VPX 1.0

A producer MAY emit a VPX 1.0 document from a 1.1 document when talking to a 1.0-only consumer. Downgrade is lossy.

| 1.1 construct | 1.0 behavior |
|---------------|--------------|
| `vpxVersion` | Set to `"1.0"`. |
| `runs`, `assessments`, `artifacts` | Dropped. |
| `findings[].fingerprint`, `reportedByRunIds`, `assessmentIds` | Dropped. |
| `proofs[].runId`, `outcome`, `limitations`, `artifactIds`, `targetSnapshot` | Dropped. Map `outcome` to deprecated `oracle.passed`: `exploited` → `true`; any other outcome → `false`. If `oracle` is missing, synthesize `{ "type": "none", "passed": <mapped> }`. |
| `verdicts[].id`, `runId`, `basedOnAssessmentIds`, `basedOnProofIds`, `supersedesVerdictId`, `approval` | Dropped except `proofId`, which is set to `basedOnProofIds[0]` or the existing `proofId`. |
| `exploitability: "not_reproduced"` | Map to `"inconclusive"`. |
| `x-*` extension properties | Dropped unless the 1.0 consumer is known to accept them. 1.0 schema uses `additionalProperties: false`. |
| Current verdict | For each `findingId`, emit only the current verdict (the one not superseded). |

After downgrade, the document MUST validate against [`../schema/vpx-1.0.schema.json`](../schema/vpx-1.0.schema.json).

---

## 21. IANA considerations

None. VPX is a media type convention, not an IANA registration at v1.1.

Suggested unofficial media type: `application/vnd.vpx+json`

---

## Appendix A — Minimal valid document

```json
{
  "vpxVersion": "1.1",
  "documentId": "550e8400-e29b-41d4-a716-446655440000",
  "target": { "baseUrl": "https://app.example.com" },
  "runs": [],
  "surfaces": [],
  "findings": [],
  "assessments": [],
  "proofs": [],
  "artifacts": [],
  "verdicts": []
}
```

## Appendix B — Normative schema

The JSON Schema at [`../schema/vpx-1.1.schema.json`](../schema/vpx-1.1.schema.json) is normative for field types and required properties. If this document and the schema disagree, the schema governs structure; this document governs semantics.

Referential integrity (§18) is normative and is enforced by [`../tools/vpx-lint.ps1`](../tools/vpx-lint.ps1) in addition to JSON Schema.

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

## Appendix D — `vpx-fingerprint-1` canonicalization

This algorithm is normative. Interoperability MUST NOT be claimed unless this procedure is used.

### D.1 Digest

```text
fingerprint.value = "sha256:" + lowercase_hex(SHA-256(UTF-8(canonical)))
fingerprint.algorithm = "vpx-fingerprint-1"
```

### D.2 Canonical string

Build nine fields in this exact order, joined by U+001F (UNIT SEPARATOR), with no trailing separator:

1. literal `vpx-fingerprint-1`
2. `repository`
3. `file`
4. `kind`
5. `source`
6. `sink`
7. `route`
8. `method`
9. `param`

Unicode NFC is applied to every field after ASCII-level normalization below. Missing values are empty strings; the field is still present.

### D.3 Field normalization

| Field | Rule |
|-------|------|
| `repository` | Trim. If the value is an `http` or `https` URL, lowercase the scheme and host; keep the path as-is except: strip a trailing `/` and a trailing `.git`. Otherwise: trim, lowercase, strip trailing `/` and trailing `.git`. |
| `file` | Trim. Replace `\` with `/`. Strip a leading `./`. Do not include commit, revision, or drive-letter prefixes beyond the repository-relative path. |
| `kind` | Trim. Lowercase. |
| `source` | `{normalized-file}:{line}` when both are known; `{normalized-file}` when only file is known; empty otherwise. `line` is a base-10 integer with no leading zeros (except `0`). Prefer an assessment location with `role: "source"`; otherwise leave empty rather than guessing. |
| `sink` | Same encoding as `source`. Prefer an assessment location with `role: "sink"`; else `origin.file` / `origin.line`. |
| `route` | Trim. If an absolute URL, take the path component only. Lowercase. Strip query and fragment. Replace consecutive `/` with one `/`. Strip a trailing `/` unless the path is `/`. |
| `method` | Trim. Uppercase. Empty if unknown. |
| `param` | Trim. Preserve case. Empty if unknown. |

### D.4 Inputs that MUST NOT be used

Producers MUST NOT include title, description, `documentId`, commit, finding `id`, or any LLM-generated prose in the fingerprint input.

### D.5 Worked example

Inputs:

- repository: `https://Github.com/acme/webapp.git/`
- file / sink: `src\\Api\\UserSearchController.cs` line `87`
- kind: `SQLi`
- route: `/api/users/`
- method: `get`
- param: `q`
- source: (unknown)

Canonical fields:

```text
vpx-fingerprint-1
https://github.com/acme/webapp
src/Api/UserSearchController.cs
sqli

src/Api/UserSearchController.cs:87
/api/users
GET
q
```

(The blank fifth field is the empty source, still bounded by U+001F.)

## Appendix E — Four-perspective guides

| Perspective | Guide |
|-------------|-------|
| Static analysis → outbound | [LLM Author Guide](../guides/LLM-AUTHOR-GUIDE.md) |
| Static analysis ← inbound | [SAST Consumer Guide](../guides/SAST-CONSUMER-GUIDE.md) |
| Black-box → outbound | [Runtime Author Guide](../guides/RUNTIME-AUTHOR-GUIDE.md) |
| Black-box ← inbound | [Runtime Author Guide](../guides/RUNTIME-AUTHOR-GUIDE.md) § Pattern A, [Implementer Guide](../guides/IMPLEMENTER-GUIDE.md) |
