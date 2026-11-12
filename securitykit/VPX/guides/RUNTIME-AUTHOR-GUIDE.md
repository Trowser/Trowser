# VPX Runtime Author Guide

Use this guide when an LLM or black-box tool (browser tester, DAST, authenticated fuzzer) **produces** VPX — with or without a prior static hypothesis.

## Two emission patterns

### Pattern A — Prove static hypotheses (inbound static VPX)

You received findings from source analysis. You add `runs[]`, `proofs[]`, `artifacts[]`, and optionally `verdicts[]`.

- Do **not** change `findings[].id` from the inbound document.
- Do **not** overwrite inbound assessments or proofs.
- Set `findings[].status` to `under_investigation` while testing, then leave as-is (verdict carries outcome).
- Append one proof per test attempt, including unsuccessful, blocked, and error attempts.
- Create one `run` per proof executor (or per distinct model/tool).

### Pattern B — Runtime-first discovery (no prior static VPX)

You discovered and confirmed a vulnerability during testing. Emit **finding + proof + verdict together** in one document:

1. Add a proof `run`.
2. Add `surfaces[]` entry (or reference existing).
3. Add `findings[]` with `status: "hypothesis"` (lifecycle) even if already confirmed — **verdict** carries `confirmed`.
4. Add `proofs[]` with matching `findingId`, `runId`, and `outcome`.
5. Add `verdicts[]` with `id`, `exploitability`, and `basedOnProofIds`.

Use `origin.tool` = your tool name (`trowser-autoscan`, `trowser-shadow`, `zap`, etc.). Omit `origin.file` when unknown.

Add `investigationHints` so source analysis can locate code later.

## Required top-level fields

```json
{
  "vpxVersion": "1.1",
  "documentId": "<uuid>",
  "target": {
    "baseUrl": "https://staging.example.com",
    "deploymentId": "<if-known>"
  },
  "runs": [],
  "surfaces": [],
  "findings": [],
  "assessments": [],
  "proofs": [],
  "artifacts": [],
  "verdicts": []
}
```

## Surface rules

1. **One surface per `(route, method)`** — deduplicate params on the surface object.
2. Set `discoveredFrom`: `"runtime"` for black-box discovery, `"static"` when copying from inbound VPX, `"openapi"` when from spec.
3. Set `routeConfidence`:
   - `"verified"` — you requested this URL and got a meaningful response.
   - `"inferred"` — route guessed from links, JS bundles, or crawl.
   - `"unknown"` — avoid unless necessary.

## Finding rules (runtime)

| Field | Guidance |
|-------|----------|
| `id` | Generate stable ID (`f-runtime-sqli-001`); keep for proof/verdict links |
| `kind` | Vulnerability category (`sqli`, `xss`, `idor`, …) |
| `severity` | Pre-proof estimate; may differ from `verdict.effectiveSeverity` |
| `title` | What you observed ("SQL error on login username field") |
| `surfaceId` + `param` | Always set when HTTP-bound |
| `origin.tool` | Your scanner name |
| `reportedByRunIds` | This proof or discovery run |
| `investigationHints` | Set when `origin.file` is unknown |

## Proof rules

Every proof MUST reference an existing `findings[].id` and a `runs[].id`. Set `outcome` explicitly.

```json
{
  "id": "proof-001",
  "findingId": "f-runtime-sqli-001",
  "runId": "run-trowser-proof",
  "executedAt": "2026-05-23T14:28:00Z",
  "outcome": "exploited",
  "tool": { "name": "trowser", "version": "1.1" },
  "workflow": { "type": "verify-workflow", "path": "..." },
  "injection": { "surfaceId": "surf-post-api-login", "param": "username", "payload": "admin'--" },
  "identity": { "name": "anonymous", "mechanism": "none" },
  "oracle": {
    "type": "error",
    "observed": true,
    "expectedSignal": "SQL syntax error in response body",
    "actualSignal": "500 body contains SQL syntax error"
  },
  "limitations": [],
  "artifactIds": ["artifact-proof-001"],
  "evidenceSummary": "POST /api/login username=admin'-- → 500, SqlException in body",
  "elapsedMs": 3200
}
```

Do **not** use deprecated `oracle.passed`. Prefer `outcome` + `oracle.observed`.

| Outcome | When |
|---------|------|
| `exploited` | Harmful effect demonstrated |
| `not-reproduced` | Attempt finished; effect not shown |
| `blocked` | Policy, WAF, auth, or environment stopped the attempt |
| `error` | Tooling failed |
| `inconclusive` | Not enough evidence to classify |

A `not-reproduced` proof MUST NOT be turned into `exploitability: "not_exploitable"` by itself. Record `limitations` (payload classes not tried, missing identity, WAF, seed data).

### `identity` on proofs

| Field | Example |
|-------|---------|
| `name` | `anonymous`, `test-user`, `admin` |
| `roles` | `["user"]` |
| `mechanism` | `session-cookie`, `bearer-jwt`, `none` |

### Artifacts

Put HTTP transcripts, screenshots, and workflow files in `artifacts[]` with a digest when possible. Reference them from `proofs[].artifactIds`. Redact cookies and tokens.

## Verdict rules

Verdicts are append-only and require `id`. Link material proofs with `basedOnProofIds` (not only deprecated `proofId`).

| Proof outcome | Typical `exploitability` | Typical `disposition` |
|---------------|--------------------------|------------------------|
| `exploited` (accepted) | `confirmed` | `fix-now` |
| Attempt done, effect not shown, impossibility not established | `not_reproduced` | `monitor` |
| Evidence shows the path cannot be exploited on this target | `not_exploitable` | `false-positive` or `accept-risk` |
| Could not complete | `inconclusive` | `monitor` |
| Safe mode / policy / WAF | `blocked` | `monitor` |

Always set `justification`. Do not use `false-positive` merely because a proof failed to reproduce.

When confirming and static `origin.file` is known (merged doc), populate `remediation.locations` from static origin.

## Investigation hints (runtime → static handoff)

When you cannot map to source code:

```json
{
  "investigationHints": {
    "codeSearchQueries": ["LoginController", "route:/api/login", "SqlException"],
    "suggestedFiles": ["**/Login*.cs", "**/auth/**"],
    "notes": "Error references dbo.Users; likely EF or raw SQL in login handler"
  }
}
```

## Oracle types

Use values from [Appendix C](../spec/VPX-1.1.md#appendix-c--oracle-vocabulary).

## Skipping already-proven findings

When consuming inbound static VPX:

- Skip findings where the **current** verdict (follow `supersedesVerdictId`) has `exploitability` other than `hypothesis`.
- Re-prove only when `rerunToken` is present (fix verification). Then append a new proof and a new verdict that supersedes the old one.

## Default payloads by kind

When inbound `proofHints.payloads` is absent:

| kind | Try |
|------|-----|
| sqli | `' OR '1'='1`, `1' AND '1'='2` |
| xss | `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>` |
| idor | adjacent IDs, `0`, `999999` |
| path-traversal | `../../../etc/passwd`, `..%2f..%2f` |
| open-redirect | `https://evil.example` |

## Example prompt block

```
You are a black-box security tester. Output VPX 1.1 (full profile) after testing.
- Include runs, assessments, proofs, artifacts, and verdicts arrays
- discoveredFrom: runtime, routeConfidence: verified on all surfaces you hit
- Each proof: runId, outcome, oracle.observed (not oracle.passed)
- Record not-reproduced and blocked attempts; do not overwrite them
- For confirmed issues: finding + proof + verdict with basedOnProofIds
- Include identity on each proof and evidenceSummary for LLM handoff
- For issues without source mapping: investigationHints with codeSearchQueries
Schema: VPX/schema/vpx-1.1.schema.json
Example: VPX/examples/runtime-only-confirmed.json
Example (disagreement): VPX/examples/multi-actor-disagreement.json
```

## Validation

Validate against `VPX/schema/vpx-1.1.schema.json` and `VPX/tools/vpx-lint.ps1` before publishing or importing into Trowser (`POST /api/vpx/import`).
