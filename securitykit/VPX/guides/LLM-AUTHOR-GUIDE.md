# VPX LLM Author Guide

Use this guide when prompting an LLM to produce VPX documents from **web application** source-code analysis. VPX is scoped to web applications with HTTP surfaces — verify the target is a web application before producing VPX output. For non-web targets (native binaries, mobile apps, desktop applications), VPX is not the right format.

## Output contract

Emit a **single JSON object** conforming to VPX 1.1 compact profile. No markdown fences in machine pipelines; fences are fine in chat.

### Required top-level fields

```json
{
  "vpxVersion": "1.1",
  "documentId": "<new-uuid>",
  "target": {
    "baseUrl": "<deployment-url-if-known>",
    "repository": "<repo-if-known>",
    "commit": "<immutable-commit-if-known>"
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

- Generate a new UUID for `documentId`.
- Include one `runs[]` entry for this analysis (`stage: "source-analysis"`, `actor.type: "llm"`).
- Leave `proofs` and `verdicts` as empty arrays — runtime tools fill these.
- `artifacts` MAY be empty. Put large model transcripts outside the document if needed.
- Include `createdAt` in ISO 8601 UTC when known.

## Rules for findings

1. **One surface per unique `(route, method)`** — reference via `surfaceId`; do not repeat route data on every finding. Use `surfaceIds` when a finding spans multiple surfaces.
2. **Every finding needs** `id`, `kind`, `severity`, `title`, `status: "hypothesis"`.
3. **Add `description`** — use this field for the vulnerability explanation. Keep `investigationHints.notes` for investigation-specific guidance.
4. **Bind runtime context** — set `surfaceId` and `param` when the vulnerability is reachable via HTTP.
5. **Bind static context** — set `origin.tool` (use `"llm-sast"`), and `origin.file` + `origin.line` when known.
6. **CWE references** — use `cwe` array (e.g. `["CWE-89"]`), not `origin.rule`. Keep `origin.rule` for scanner-specific rule IDs.
7. **Trace is short** — max 5 steps, arrow-separated flow descriptions, no full file contents.
8. **Proof hints for medium+ severity** — include `proofHints.category` and `proofHints.oracle`.
9. **Related findings** — use `relatedFindingIds` when findings form attack chains.
10. **Fingerprint when possible** — compute `vpx-fingerprint-1` from repository, file, kind, source/sink, route, method, and param. Never fingerprint from title or description alone. See [Appendix D](../spec/VPX-1.1.md#appendix-d--vpx-fingerprint-1-canonicalization).
11. **Attribute the report** — set `reportedByRunIds` to this run and add a matching assessment.
12. **Do not invent proof results** — never populate `proofs` or `verdicts` unless you are the runtime or adjudication actor.

## Assessments

For each finding you support, add one assessment:

```json
{
  "id": "assessment-sqli-001",
  "findingId": "f-sqli-001",
  "runId": "run-llm-sast",
  "phase": "source-analysis",
  "conclusion": "supports",
  "confidence": 0.72,
  "rationale": "Untrusted query input is interpolated into SQL.",
  "locations": [
    { "file": "src/Api/UserSearchController.cs", "line": 87, "role": "sink" }
  ]
}
```

If you disagree with another model's report, emit `conclusion: "disputes"` or `"inconclusive"` — do not delete their assessment.

Do not treat your `confidence` as calibrated against other models.

## Non-HTTP findings

For code-only issues (hardcoded secrets, weak crypto) with no HTTP reachability:

- Include `origin` only; omit `surfaceId`, `param`, and `proofHints`.
- Use `status: "deferred"` or low `proofPriority`.
- Do not invent surfaces.

See [§13 Code-only findings](../spec/VPX-1.1.md#13-code-only-findings-no-http-surface).

## Route confidence

When inferring routes from code, set on the surface:

- `discoveredFrom: "static"` or `"inferred"`
- `routeConfidence: "inferred"` unless confirmed by OpenAPI or tests

## Preserve finding IDs

When the same finding will be proven by a black-box tool, **keep `findings[].id` stable** — proofs, assessments, and verdicts reference it. Use `fingerprint` for cross-document correlation.

## Severity mapping

| Condition | Severity |
|-----------|----------|
| Unauthenticated RCE, auth bypass, full DB read | `critical` |
| Authenticated SQLi, stored XSS, IDOR on sensitive data | `high` |
| Reflected XSS, CSRF on state change, path traversal | `medium` |
| Info leak, missing headers, verbose errors | `low` |
| Best-practice, defense-in-depth | `info` |

## Kind values

Prefer: `sqli`, `xss`, `csrf`, `idor`, `ssrf`, `open-redirect`, `path-traversal`, `mass-assignment`, `ssti`, `command-injection`, `deserialization`, `header-injection`, `auth-bypass`, `info-leak`, `misconfiguration`, `other`.

## Oracle hints

Tell the proof executor what signal to expect:

| kind | suggested `proofHints.oracle` |
|------|-------------------------------|
| sqli | `error-or-timing` |
| xss | `reflection` or `dom-change` |
| csrf | `status-code` or `dom-change` |
| idor | `status-code` |
| ssrf | `network-match` |
| open-redirect | `status-code` |

## Identity hints

| Scenario | `proofHints.identity` |
|----------|------------------------|
| No login required | `anonymous` |
| Normal user session | `authenticated-user` |
| Admin-only endpoint | `admin` |

## Token budget

Typical compact document:

- 10 surfaces ≈ 1 KB
- 50 findings ≈ 12–20 KB
- Avoid `snippet` unless it clarifies a non-obvious sink (≤ 200 chars)
- Keep `rationale` to one or two sentences

## Example prompt block

```
Analyze the repository for security vulnerabilities. Output a VPX 1.1 document
(JSON only, compact profile). Use vpxVersion "1.1", generate documentId UUID,
include runs/surfaces/findings/assessments/proofs/artifacts/verdicts arrays
(proofs, artifacts, and verdicts empty). status "hypothesis" on all findings.
Deduplicate HTTP surfaces. Include one source-analysis run and one assessment
per finding. Include proofHints for severity medium and above. Compute
vpx-fingerprint-1 when repository, file, kind, route, method, and param are known.
Schema: VPX/schema/vpx-1.1.schema.json
```

## Validation

Validate output against `VPX/schema/vpx-1.1.schema.json` and lint with `VPX/tools/vpx-lint.ps1` before sending to a proof executor.

## After proof

Do not edit the hypothesis document in place unless you are the triage owner. Executors append `proofs` and assessments. Adjudicators append `verdicts`. Fix agents consume `verdicts[].remediation` only.
