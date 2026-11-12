# VPX Changelog

All notable changes to the Vulnerability Proof eXchange format.

## [1.1] — 2026-08-28

Multi-actor analysis and proof. Spec: [`spec/VPX-1.1.md`](./spec/VPX-1.1.md). Schema: [`schema/vpx-1.1.schema.json`](./schema/vpx-1.1.schema.json).

### Document model

- Added required top-level arrays `runs`, `assessments`, and `artifacts` (each MAY be empty)
- Conformance schema uses `additionalProperties: true` on evolving objects
- Consumers MUST ignore unknown properties and SHOULD preserve them; experimental fields SHOULD use an `x-` prefix
- Consumers SHOULD accept later `1.x` minor versions and reject `2.0` unless explicitly supported

### Target, runs, and assessments

- `target` adds `deploymentId`, `sourceDigest`, and `buildDigest`; `commit` SHOULD be immutable
- `runs[]` records one bounded execution (`source-analysis`, `proof`, `aggregation`, `adjudication`, `fix`, `rerun`) and an `actor`
- `assessments[]` preserve independent `supports` / `disputes` / `inconclusive` opinions with rationale and optional confidence

### Findings and proofs

- `findings[].fingerprint` uses normative `vpx-fingerprint-1` canonicalization (Appendix D)
- Findings may list `reportedByRunIds` and `assessmentIds`
- Proofs are append-only; `runId` and `outcome` are required (`exploited`, `not-reproduced`, `blocked`, `error`, `inconclusive`)
- `oracle.passed` is deprecated in favor of `oracle.observed` / `expectedSignal` / `actualSignal`
- Proofs MAY record `limitations`, `targetSnapshot`, `preconditions`, `cleanup`, and `artifactIds`

### Verdicts and merge

- Verdicts require `id` and are append-only; `supersedesVerdictId` establishes history
- `basedOnProofIds` and `basedOnAssessmentIds` replace relying on a single `proofId` (`proofId` remains for 1.0)
- Exploitability adds `not_reproduced`; a `not-reproduced` proof MUST NOT auto-produce `not_exploitable`
- Merge rules: union/append by id; fingerprint conflicts and artifact digest conflicts are merge errors; unknown properties are preserved

### Tooling and examples

- Strict linter: `tools/vpx-lint.ps1` (referential integrity + unknown-property warnings)
- Fingerprint helper: `tools/vpx-fingerprint.ps1`
- Downgrade 1.1 → 1.0: `tools/vpx-downgrade.ps1` (lossy; see spec §20)
- Example `examples/multi-actor-disagreement.json` (three source models, three proof outcomes)
- Merge fixtures under `examples/merge/`

## [1.0.1] — 2026-07-21

Spec and schema refinements based on external LLM reviewer feedback (3 sessions).

### Bug fixes

- **§1.4:** Fixed "five" → "four" top-level arrays (was listing four but saying five)
- **§1.2:** Added explicit web-application scope statement — VPX targets web apps with HTTP surfaces
- **§7:** Retitled from "Non-HTTP findings" to "Code-only findings (no HTTP surface)" with scoping sentence
- **Schema:** Constrained `oracle.evidence` from unconstrained `{}` to `{ "type": ["string", "object"] }`

### Schema additions (finding properties)

- `description` — human-readable vulnerability description (max 2000 chars), separates "what" from `investigationHints` "how to investigate"
- `surfaceIds` — array of surface IDs for findings spanning multiple surfaces
- `owasp` — OWASP category identifier (e.g. `"A05"`)
- `cwe` — array of CWE identifiers (e.g. `["CWE-89"]`), separate from `origin.rule`
- `relatedFindingIds` — cross-references for attack chains and amplification
- `tags` — free-form labels for filtering and grouping
- `reference` — URL or external reference identifier
- `remediation` — short prose remediation guidance (max 2000 chars); distinct from structured `verdict.remediation`

### Schema additions (document root)

- `profile` — signals which profile constraints apply: `"compact"`, `"full"`, or `"summary"`

### Oracle vocabulary

- Added `data-change` oracle type (persistent side-effects: database records, file creation)

### Spec clarifications

- §5.8: Clarified that `findings[].confidence` (hypothesis confidence) is distinct from `verdicts[].confidence` (triage certainty)
- §6.1: Added profile length conventions table (compact conventions vs. schema maximums for `trace`, `snippet`, `notes`, `payloads`)
- §10.2: Documented `templateId` null-vs-empty-string behavior
- §5.9: New section documenting classification fields (`owasp`, `cwe`, `reference`, `remediation`)
- §5.10: New section documenting relationship fields (`relatedFindingIds`, `tags`)

### Guides

- LLM Author Guide: added web-application scope check, `description` field guidance, `cwe` usage, `relatedFindingIds` guidance

### Examples

- Updated `compact-hypotheses.json` with `profile`, `description`, `cwe`, `owasp`, `surfaceIds`, `relatedFindingIds`, `tags`, `data-change` oracle
- Updated `non-http-finding.json` with `profile`, `description`, `cwe`, `tags`

## [1.0] — 2026-05-23

Initial public release.

- Core document model: `target`, `surfaces`, `findings`, `proofs`, `verdicts`
- Exploitability lifecycle and disposition enums
- Compact and full profiles
- Document composition (merge) rules
- Extended fields: `discoveredFrom`, `routeConfidence`, `investigationHints`, proof `identity`, `evidenceSummary`
- Non-HTTP findings guidance
- Appendix C — Oracle vocabulary
- Four-perspective guides: LLM Author, SAST Consumer, Runtime Author, Implementer
- Examples: compact hypotheses, merged static+runtime, runtime-only confirmed
- JSON Schema at `schema/vpx-1.0.schema.json`
- Trowser import (`POST /api/vpx/import`) and export (`GET /api/vpx/export`)
