# VPX — Vulnerability Proof eXchange

**Version 1.1** · [Specification](./spec/VPX-1.1.md) · [JSON Schema](./schema/vpx-1.1.schema.json)  
Previous: [VPX 1.0](./spec/VPX-1.0.md)

VPX is a lightweight JSON format for exchanging vulnerability **hypotheses**, independent **assessments**, runtime **proof** attempts, external **artifacts**, and adjudicated **verdicts**.

It closes the gap that SARIF and SBOM formats leave open: *proving whether a reported vulnerability is an actual exploitable threat in your deployed application* — without erasing disagreement or failed attempts.

## Four perspectives

VPX is designed for all actors in the analysis loop:

| Perspective | Role | Guide |
|-------------|------|-------|
| **Source analysis → out** | Report hypotheses with code trace, fingerprint, and proof hints | [LLM Author Guide](./guides/LLM-AUTHOR-GUIDE.md) |
| **Source analysis ← in** | Consume proofs/verdicts; fix code; merge triage | [SAST Consumer Guide](./guides/SAST-CONSUMER-GUIDE.md) |
| **Black-box → out** | Prove or discover; emit proofs, artifacts, and verdicts | [Runtime Author Guide](./guides/RUNTIME-AUTHOR-GUIDE.md) |
| **Black-box ← in** | Import static VPX; queue proofs | [Runtime Author Guide](./guides/RUNTIME-AUTHOR-GUIDE.md) § Pattern A |

See [Document composition](./spec/VPX-1.1.md#15-document-composition) for merge rules when combining documents.

## Why VPX exists

Modern source analysis — especially multi-model LLM review — produces more findings than teams can fix, and models often disagree. Organizations set CVSS caps and defer lower-severity issues, but deferral without evidence is guesswork.

VPX 1.1 supports a practical multi-actor workflow:

1. **Hypothesize** — each analysis actor records an assessment; equivalent reports share a fingerprint.
2. **Prove** — a runtime tool tests whether a real session can trigger harmful effects. Every attempt is kept, including `not-reproduced` and `blocked`.
3. **Adjudicate** — a verdict references the assessments and proofs that were considered.
4. **Remediate and rerun** — a new verdict supersedes the previous one after a fix.

## Quick start

| Audience | Start here |
|----------|------------|
| Humans | [VPX 1.1 Specification](./spec/VPX-1.1.md) |
| Static analysis LLM (out) | [LLM Author Guide](./guides/LLM-AUTHOR-GUIDE.md) |
| Static analysis LLM (in) | [SAST Consumer Guide](./guides/SAST-CONSUMER-GUIDE.md) |
| Black-box / runtime LLM | [Runtime Author Guide](./guides/RUNTIME-AUTHOR-GUIDE.md) |
| Tool implementers | [Implementer Guide](./guides/IMPLEMENTER-GUIDE.md) |
| Validators | [JSON Schema](./schema/vpx-1.1.schema.json) and [linter](./tools/vpx-lint.ps1) |
| Examples | [examples/](./examples/) — including [multi-actor disagreement](./examples/multi-actor-disagreement.json) |

## Document structure (minimal)

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

- **`runs`** — provenance for each analysis, proof, aggregation, or adjudication execution.
- **`surfaces`** — deduplicated HTTP attack surfaces (route, method, params, auth, route confidence).
- **`findings`** — vulnerability hypotheses linked to surfaces and/or code origin, with optional fingerprint.
- **`assessments`** — independent opinions (`supports` / `disputes` / `inconclusive`).
- **`proofs`** — append-only runtime attempts with an explicit `outcome`.
- **`artifacts`** — metadata and digests for evidence stored outside the document.
- **`verdicts`** — append-only triage outcomes; history uses `supersedesVerdictId`.

## Profiles

| Profile | Use |
|---------|-----|
| **compact** | LLM output and token-sensitive pipelines. Omits optional fields; short traces. |
| **full** | Audit, export, and evidence bundles. All fields present when known. |
| **summary** | Non-normative condensed view for a first LLM call. |

See [§12 Profiles](./spec/VPX-1.1.md#12-profiles) in the specification.

## Tools

```powershell
pwsh -File tools/vpx-lint.ps1 -InputPath examples\compact-hypotheses.json
pwsh -File tools/vpx-fingerprint.ps1 -Repository github.com/acme/webapp -Kind sqli -Route /api/users -Method GET -Param q
pwsh -File tools/vpx-downgrade.ps1 -InputPath in-1.1.json -OutputPath out-1.0.json
```

The linter checks referential integrity and warns about unknown unnamespaced properties. JSON Schema remains the conformance validator for types and required fields.

## Reference implementation

[Trowser](https://github.com/Trowser/Trowser) implements VPX 1.1 import and export (and still accepts VPX 1.0 on import):

- `POST /api/vpx/import` — ingest hypotheses from static analysis
- `GET /api/vpx/export` — export merged session state

See [Implementer Guide](./guides/IMPLEMENTER-GUIDE.md#trowser-reference).

## Versioning

VPX uses semantic versioning on the format: `vpxVersion: "1.1"`. Consumers SHOULD accept later `1.x` minor versions. Breaking changes increment the major version. VPX 1.0 documents remain readable; see [downgrade](./spec/VPX-1.1.md#20-downgrade-from-vpx-11-to-vpx-10).

See [CHANGELOG.md](./CHANGELOG.md).

## License

VPX specification files are released under the same license as the Trowser project. See [LICENSE](./LICENSE).
