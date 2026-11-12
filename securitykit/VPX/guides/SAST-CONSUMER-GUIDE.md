# VPX SAST Consumer Guide

Use this guide when an LLM or static-analysis pipeline **reads** VPX produced by black-box testing, other investigations, or merged triage documents — and must update code analysis, prioritization, or fix suggestions.

## Your job

You receive runtime truth plus preserved disagreement. Your outputs are:

- Updated triage (accept, re-open, downgrade static findings)
- Targeted re-analysis (which files/routes to inspect)
- Fix patches or PR suggestions from `verdicts[].remediation`
- Revised static VPX (corrected routes, dismissed false positives) **without deleting** inbound assessments or proofs

## Read order

Process a VPX document in this order:

1. **`target`** — confirm repository/commit/`deploymentId` matches your codebase and the tested build.
2. **`runs[]`** — who produced each assessment and proof.
3. **Current `verdicts[]`** — follow `supersedesVerdictId`; do not pick by array order or timestamp alone.
4. **`assessments[]`** — independent opinions; disagreement is signal.
5. **`proofs[]`** — every attempt, including `not-reproduced` and `blocked`.
6. **`findings[]`** — match to your prior work by `id`, then `fingerprint`.
7. **`surfaces[]`** — HTTP entry points; use `routeConfidence` before trusting routes.
8. **`artifacts[]`** — verify `digest` before relying on external evidence.

Skip re-proving findings that already have a current verdict unless `rerunToken` indicates fix verification is requested.

## Verdict decision tree

| `exploitability` | `disposition` (typical) | SAST action |
|------------------|-------------------------|-------------|
| `confirmed` | `fix-now` / `fix-scheduled` | Open fix task; use `remediation` + `findings[].origin` |
| `not_exploitable` | `accept-risk` | Code flaw may exist; mark **environment-mitigated** — do not delete static finding silently |
| `not_exploitable` | `false-positive` | Remove or downgrade matching static finding **only if** the source hypothesis is refuted |
| `not_reproduced` | `monitor` | Keep static finding. Failed runtime tests are not proof of impossibility |
| `inconclusive` | `monitor` | Keep static finding; note blockers (auth, WAF, env) |
| `blocked` | `monitor` | Proof not run; no change to static severity |
| `deferred` | — | Below policy threshold; static finding stays |
| `hypothesis` | — | No runtime test yet; static finding unchanged |

### `false-positive` vs `not_exploitable` vs `not_reproduced`

These are **not** interchangeable:

- **`false-positive`** — the vulnerability report was wrong (bad route, wrong sink, parameterized already, unreachable). Requires reasoning about the **source** hypothesis.
- **`not_exploitable`** — attack did not succeed **and** evidence establishes that exploitation is prevented for the identified target and conditions.
- **`not_reproduced`** — attempts did not demonstrate the effect; impossibility was **not** established. **Keep** the static finding.

A `not-reproduced` proof MUST NOT be treated as `not_exploitable` or `false-positive` by itself.

## Matching findings across documents

When merging static VPX (Document A) with runtime VPX (Document B):

| Priority | Match key |
|----------|-----------|
| 1 | Exact `findings[].id` |
| 2 | Matching `fingerprint.value` (`vpx-fingerprint-1`) |
| 3 | `(surfaceId, param, kind)` |
| 4 | `(route, method, param, kind)` from resolved surface |

Conflicting fingerprints for the same `id` are a **merge error**. Two different ids with the same fingerprint need human review — do not silently merge.

**Merge rule:** Union findings by `id`. Append assessments and proofs; never replace them. Append verdicts; use `supersedesVerdictId` for history.

See [Document composition](../spec/VPX-1.1.md#15-document-composition).

## Using `remediation`

When `verdicts[].remediation` is present:

1. Prefer `locations[].file` + `line` over free-text titles.
2. Treat `codeHint` as illustrative — verify against actual code before applying.
3. If `locations` is empty but `findings[].origin.file` exists, use origin from the matched finding.
4. If both are empty (runtime-only discovery), use `findings[].investigationHints` to locate code.

## Runtime-only findings (no static origin)

Black-box tools may emit findings with `surfaceId` but **no** `origin.file`. For these:

1. Read `surfaces[]` for route, method, params, auth.
2. Read `findings[].investigationHints.codeSearchQueries` if present.
3. Search the repository for route handlers, controller names, or param names.
4. Emit an **updated static VPX** with filled `origin` and a new assessment — do not delete the runtime proof.

## `routeConfidence` on surfaces

| Value | SAST action |
|-------|-------------|
| `verified` | Trust route for handler lookup |
| `inferred` | Search multiple candidate handlers; confirm with OpenAPI or framework routes |
| `unknown` | Do not auto-map to code; treat as investigation queue |

## Token-efficient consumption

For large documents, read only:

```
target + current verdicts + assessments[].conclusion + proofs[].outcome
```

Then drill into full `proofs[]`, `assessments[]`, and `findings[]` for `fix-now` and `confirmed` only.

## Example prompt block

```
You received a VPX 1.1 document from runtime proof testing.
1. Resolve the current verdict per finding via supersedesVerdictId.
2. For exploitability "confirmed", produce a fix using remediation and origin.
3. For "false-positive", list static finding IDs to remove only if the source path is refuted.
4. For "not_reproduced", keep the static finding; summarize proof limitations.
5. For runtime-only findings (no origin.file), output investigationHints-driven code search queries.
Do not re-run proofs. Do not drop assessments or unsuccessful proofs. Output a brief triage summary plus code changes for fix-now items.
```

## Validation

Ensure inbound document validates against `VPX/schema/vpx-1.1.schema.json` (or 1.0 schema if `vpxVersion` is `"1.0"`) and lint 1.1 documents with `VPX/tools/vpx-lint.ps1`.
