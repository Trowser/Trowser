# VPX 1.1 merge conformance fixtures

These documents illustrate §15 merge rules. They are valid VPX 1.1 documents on their own; the **expected** files show a successful merge, while the **conflict** and **ambiguous** pairs MUST NOT be auto-merged.

| Fixture | Rule |
|---------|------|
| `ok-union-*` | Union by id; append proofs and assessments; keep both runs |
| `conflict-fingerprint-*` | Same finding `id`, different `fingerprint.value` → merge error |
| `ambiguous-cluster-*` | Two findings with the same fingerprint but different ids → human review, do not silently merge |

A merge implementation SHOULD record automatic correlation as an aggregation `run`.
