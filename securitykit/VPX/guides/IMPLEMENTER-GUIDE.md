# VPX Implementer Guide

Guide for tools that consume, produce, or validate VPX documents.

## Validation

Normative schema: [`../schema/vpx-1.1.schema.json`](../schema/vpx-1.1.schema.json)  
VPX 1.0 schema (legacy): [`../schema/vpx-1.0.schema.json`](../schema/vpx-1.0.schema.json)  
Linter (referential integrity + unknown-property warnings): [`../tools/vpx-lint.ps1`](../tools/vpx-lint.ps1)

```bash
# Example with ajv-cli (npm) — conformance (unknown properties allowed)
ajv validate -s VPX/schema/vpx-1.1.schema.json -d document.json --spec=draft7

# Referential integrity and misspelling warnings
pwsh -File VPX/tools/vpx-lint.ps1 -InputPath document.json
```

Reject documents with a different **major** version. Forward-compatible parsers MUST accept later `1.x` minor versions and ignore unknown properties. A 1.1 consumer MUST accept `vpxVersion: "1.0"` on import.

A lint warning MUST NOT make an otherwise conforming document unreadable.

## `vpx-fingerprint-1`

Implement [Appendix D](../spec/VPX-1.1.md#appendix-d--vpx-fingerprint-1-canonicalization) exactly before claiming interoperability.

```powershell
pwsh -File VPX/tools/vpx-fingerprint.ps1 `
  -Repository https://github.com/acme/webapp `
  -File src/Api/UserSearchController.cs `
  -Kind sqli -SinkFile src/Api/UserSearchController.cs -SinkLine 87 `
  -Route /api/users -Method GET -Param q
```

Never hash title or description as the sole input.

## Producer roles

| Role | Writes | Reads |
|------|--------|-------|
| Static / LLM analyzer | `findings`, `surfaces`, `target`, `runs`, `assessments` | `verdicts`, `proofs` (via [SAST Consumer Guide](./SAST-CONSUMER-GUIDE.md)) |
| Runtime / black-box tester | `proofs`, `runs`, `artifacts`, optional `verdicts` | `findings`, `surfaces`, `proofHints` (via [Runtime Author Guide](./RUNTIME-AUTHOR-GUIDE.md)) |
| Adjudicator | `verdicts`, adjudication `runs` | assessments, proofs |
| Triage dashboard | `verdicts`, `policy` | all |
| Fix agent | patches code | `verdicts[].remediation` |

## Proof executor checklist

1. Parse `findings` where `status` is `hypothesis` or `under_investigation`.
2. Sort by `proofPriority` descending (compute if absent: `cvss * confidence * 10`).
3. Resolve `surfaceId` → route, method, params, auth.
4. Apply `proofHints.identity` (session bootstrap).
5. Run injection using `proofHints.payloads` or tool defaults.
6. Evaluate oracle per `proofHints.oracle`.
7. Append a `proofs[]` entry with `runId`, `executedAt`, `outcome`, `oracle.observed`, optional `artifactIds` and `limitations`. Never overwrite a prior proof.
8. Write a **new** `verdicts[]` row with `id` and `basedOnProofIds`. Do not map `not-reproduced` to `not_exploitable` automatically.
9. On fix, accept `rerunToken`, append a new proof, and issue a verdict with `supersedesVerdictId`.

## Linking proofs to findings

Proof executors SHOULD accept an explicit link field in workflow metadata:

```json
{
  "vpxFindingId": "f-sqli-001",
  "phases": { "setup": [], "trigger": [], "oracle": {}, "cleanup": [] }
}
```

If omitted, match by `(surface route, method, param)` or attach to the nearest finding by `kind`.

## Exploitability → disposition defaults

| exploitability | suggested disposition |
|----------------|----------------------|
| `confirmed` | `fix-now` or `fix-scheduled` (if below cvssCap) |
| `not_exploitable` | `false-positive` or `accept-risk` (only with source-hypothesis reasoning) |
| `not_reproduced` | `monitor` |
| `inconclusive` | `monitor` |
| `blocked` | `monitor` |
| `deferred` | (no disposition required) |

Always set `justification` for `accept-risk` and `false-positive`.

## Merge

Implement [§15](../spec/VPX-1.1.md#15-document-composition). Fixtures: [`../examples/merge/`](../examples/merge/).

- Conflicting fingerprints for the same finding id → merge error
- Artifact digest conflict for the same id → merge error
- Ambiguous fingerprint clusters → human review
- Preserve unknown properties including `x-*`

## Downgrade to 1.0

Lossy. Use [`../tools/vpx-downgrade.ps1`](../tools/vpx-downgrade.ps1) or follow [§20](../spec/VPX-1.1.md#20-downgrade-from-vpx-11-to-vpx-10).

## Trowser reference

Trowser implements VPX 1.1 import and export and accepts VPX 1.0 on import:

```
POST /api/vpx/import          — ingest VPX (mode: merge | replace; action: clear)
GET  /api/vpx/export          — export merged session state (vpxVersion 1.1)
GET  /api/vpx/export?profile=full
```

**Gate-free** — allowed in safe mode.

### Import (`POST /api/vpx/import`)

Body: full VPX document, or `{ "document": { ... }, "mode": "merge" }`.

| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `merge` | `merge` skips duplicate finding IDs; `replace` clears prior import |
| `action` | — | `clear` removes imported VPX session state |

Registers findings as chain-findings (`source: vpx-import`), surfaces, runs, assessments, proofs, artifacts, and verdicts for proof queue and re-export.

### Export (`GET /api/vpx/export`)

| VPX section | Trowser source |
|-------------|----------------|
| `target` | Import target or current browser URL origin |
| `runs` | Imported runs plus a Trowser session run |
| `surfaces` | Imported surfaces merged with session findings |
| `findings` | Shadow, auto-scan, manual, **vpx-import** (with fingerprints when computable) |
| `assessments` | Imported assessments |
| `proofs` | Imported + session `verify-workflow` / `chain-prove` (`outcome`, `runId`) |
| `artifacts` | Imported artifacts; evidence bundles referenced when present |
| `verdicts` | Imported + derived from proofs (`not_reproduced` rather than auto `not_exploitable`) |

### Proof recording

When `verify-workflow` or `chain-prove` completes, Trowser records a proof if the workflow includes:

```json
{ "vpxFindingId": "f-sqli-001", ... }
```

Or if `exportEvidence: true` is set (links to best-matching finding by endpoint/kind).

### MCP

```
browser_vpx_import  — document, mode, action: clear
browser_vpx_export  — profile: compact | full
```

## File layout reference

```
VPX/
  README.md                 — overview
  spec/VPX-1.1.md           — normative specification
  spec/VPX-1.0.md           — previous specification
  schema/vpx-1.1.schema.json
  schema/vpx-1.0.schema.json
  tools/vpx-lint.ps1
  tools/vpx-fingerprint.ps1
  tools/vpx-downgrade.ps1
  examples/                 — valid 1.1 documents
  examples/merge/           — merge conformance fixtures
  guides/
    LLM-AUTHOR-GUIDE.md
    SAST-CONSUMER-GUIDE.md
    RUNTIME-AUTHOR-GUIDE.md
    IMPLEMENTER-GUIDE.md    — this file
  CHANGELOG.md
```

## Media type

Unregistered. Suggested: `application/vnd.vpx+json`

## Versioning

Check `vpxVersion`. Implement parsers for `"1.0"` and `"1.1"` (and later `1.x`). Reject `"2.0"` until a 2.0 spec exists.
