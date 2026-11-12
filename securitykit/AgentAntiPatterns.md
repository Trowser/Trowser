# Agent anti-patterns (security testing)

Short list of habits that produce false CRITICAL filings or incomplete coverage when driving Trowser via MCP/REST.

## Do not trust `testPriority` alone

Attack-surface `testPriority` is a heuristic rank, not a permission to ignore endpoints. Login, search/query sinks, and responses that dump `password`/`token` fields are boosted, but **always** reserve a pass for:

- the primary login form/API
- the primary search/`q` parameter when present

Prefer `scope.targetUrl` for focused probes over assuming low-priority endpoints are safe.

## Do not ignore `suppressedFindings` / `skippedByBudget`

- Playbook and auto-scan responses may keep lower-severity duplicates in **`suppressedFindings`**. Read them before declaring a sink clean.
- Dry-run / playbook results with **`coverageIncomplete: true`** or steps marked **`skippedByBudget`** are incomplete. Raise budget to `recommendedBudget` (from dry-run) before treating an empty finding list as a clean bill of health.

## Do not file CRITICAL without proof

Require one of:

- SQL **error signatures** or confirmed boolean/oracle evidence (not body growth alone on POSTs that store content)
- XSS with **active DOM / sink** corroboration (`payloadRendered` / `Dom.Dangerous` / sink reach) — not “confirmed” + “not rendered” together
- Authz evidence with **response bodies** (`fetch/batch` + `includeBodies: true`), not status codes alone

When severity is medium/low and the summary says the payload was not active in the DOM, do not escalate to CRITICAL.

## Do not click ambiguous `byText`

`byText` / text locators that match multiple controls (or chrome vs content) cause wrong navigation and stale refs. Prefer:

1. `browser_snapshot` → **ref** numbers
2. Semantic locators with a unique accessible name
3. Re-snapshot after navigation — never reuse refs across page changes

## Budget anti-pattern

Calling `a05a` / `auto-scan` with the default `maxSeconds: 120` and then stopping is an anti-pattern. Canonical flow:

1. `POST /api/orchestrate/dry-run/{id}`
2. Copy `recommendedBudget`
3. Run the playbook
4. If `coverageIncomplete`, re-run with a higher envelope — do not invent CRITICAL findings to fill the gap
