# Trowser offline regression suite

Oracle-backed API/functional regression tests. Each test builds a deterministic target **in memory** via `MockResponse` / intercept helpers, then asserts on result *content* (not merely “didn’t throw”).

No Docker, no live internet dependency for the core suite, no unit-test framework — just `Trowser.exe --run` and process exit codes.

## Quick start

```powershell
# From repo root (uses Release publish exe if present, else Debug)
.\tests\regression\run-regression.ps1

# Subset
.\tests\regression\run-regression.ps1 -Filter "01-*"
.\tests\regression\run-regression.ps1 -Filter "*headers*"

# Explicit exe
.\tests\regression\run-regression.ps1 -Exe "src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe"

# Fast loop against an already-running instance (API must be on)
.\tests\regression\run-regression.ps1 -Fast -Key "your-api-key" -Port 6923
```

Exit code `0` = all tests passed; `1` = one or more failures/errors. Per-test detail is written to [`results.txt`](results.txt).

## Layout

| Path | Role |
|------|------|
| [`_prelude.csx`](_prelude.csx) | Shared helpers (`SetupPage`, `VulnerableHeaders` / `SecureHeaders` / `ScriptableHeaders`, JWT/SAML/OIDC seeds, …) |
| [`functional/*.csx`](functional/) | API correctness oracles |
| [`security/*.csx`](security/) | Detection oracles (positive + clean twin where possible) |
| [`_calibration/`](_calibration/) | Manual calibration probes (not in the default suite) |
| [`run-regression.ps1`](run-regression.ps1) | Concatenates prelude + test → `Trowser.exe --run` |

The Roslyn script engine has no `#load` source resolver; the runner concatenates `_prelude.csx` ahead of each test into a temp file.

## How fixtures work

Trowser’s `WebResourceRequested` handler can fulfill the **top-level document** (and subresources) with arbitrary status, body, and **response headers**. Tests therefore:

1. `SetupPage(url, html, headers)` / `SetupApi(...)`
2. `Navigate` / `Fetch` / run scanners
3. Assert on findings, snapshots, titles, etc.

Use `ScriptableHeaders()` (CSP allows `'unsafe-inline'`) for pages whose fixtures need inline `<script>`. Prefer `SecureHeaders()` / `VulnerableHeaders()` for header/CSP oracles.

Fixture host: `https://trowser-regression.test` (never contacts a real network when mocked).

## Coverage matrix

### Functional (Tier 1)

| Test | What it proves |
|------|----------------|
| `01-navigation` | Mocked doc navigate, title/text, 404/500 bodies, back/forward |
| `02-inspection` | Headings, links, interactive elements, snapshot |
| `03-interaction-locators` | `ByRole` / `ByLabel` / `ByText` / `ByPlaceholder`, Type/Select/Click/Hover/PressKey |
| `04-waiting` | `WaitForElement`, `WaitForRequest` with delayed content/API |
| `05-console-network` | Console capture + network log status for mocked XHR |
| `06-storage-cookies` | Cookie jar + local/session storage round-trip, `ClearSession` |
| `07-mock-intercept-fetch` | `MockResponse` + `Fetch` body/status; intercept rule CRUD |
| `08-audits` | a11y unlabeled/alt oracles + clean twin; HTML errors; broken `.invalid` links; consistency runs |
| `10-new-window-opener` | `window.open` preserves `window.opener` via `NewWindow` assignment |
| `11-multipart-upload` | Local HttpListener: `SetFileInput` + `fetch(FormData)` and form POST deliver non-empty file bytes (WebView2 multipart stream preservation) |
| `17-sse-stream` | Mocked `EventSource` + `RunSseAuditAsync` on fixture `text/event-stream` body |
| `17-sse-fetch-open-stream` | Local HttpListener: `fetch()` + `ReadableStream` on a chunked live SSE; capture while `state: open`, then `AbortController` + listener shutdown |

### Security static oracles (Tier 1)

| Test | Positive oracle | Clean twin |
|------|-----------------|------------|
| `01-headers` | Missing CSP/HSTS/XFO/… (+ Server / X-Powered-By) | `SecureHeaders()` → 0 findings |
| `02-cookies` | Missing Secure/HttpOnly on session cookie | Secure+HttpOnly+SameSite → 0 |
| `03-dom-xss` | `javascript:`, inline handlers, sinks | Fewer / no high findings |
| `04-mixed-sri-sourcemaps` | Mixed content, missing SRI, inline `sourceMappingURL` | No mixed content; SRI present |
| `05-retire-secrets-jwt` | jQuery 1.6.0 CVE; Bootstrap 3.4.1 + jQuery UI inside `app.bundle.min.js` (func + filecontent); JWT in storage; `alg:none` | No libs; fewer secrets; not `alg:none` |
| `06-cors-saml-oidc-graphql` | CORS reflects `evil.com`+credentials; SAML decode; OIDC/GraphQL run | CORS clean |

### Active scanners (Tier 2)

| Test | Status |
|------|--------|
| `07-active-scanners` | **Structural** for SQLi / AutoScan / CSRF (static mocks lack differential server behavior; AutoScan may also hit real DNS for discovery helpers). Path-traversal can FLAG when mock returns `passwd`-like bodies — treated as best-effort, not a hard true-positive gate. |
| `11-auth-control-identifier` | Local `HttpListener` oracle: session cookie **enforced**, tracking cookie **presence-only**, `Authorization` **enforced**, `RequestVerificationToken` **ignored**. |
| `08-cache-map` | Tech-stack cache identify: `CF-Cache-Status: HIT` + `Age` → `cache.detected`; `no-store` twin → not detected. Map/pollution are structural (HttpClient bypasses WebView mocks). |
| `09-http-smuggling` | Offline oracles: TE-TE same-class status is clean; Via-only passive is not elevated; CL.TE/TE.CL builders stay PortSwigger-shaped. Live desync TP is not mocked. |
| `10-whisper-clues` | GET-password + hidden inputs are clues; CSP/javascript: are not (Shadow); same clue not in `newClues` on second visit; cache/tech once per domain; Copy bundle includes details. Internal comment / FAQ textarea is not `chat-ui`; Intercom global is. |
| `12-runtime-sensor` | Shared runtime sensor: innerHTML sink + client-surface inventory; trace-input `monitorSinks` returns instrumented list |
| `13-postmessage` | Origin-check grading (none/weak/strict) + synthetic MessageEvent fuzz |
| `14-client-prototype-pollution` | URL `__proto__[x]` merge pollutes; allowlisted clean twin does not |
| `15-xs-leaks` | img-error differential (mocked victim resources), watermarked PoC, existence-only → informational tier, posture block |

## Known gaps (from calibration)

| Capability | Offline true-positive? | Notes |
|------------|------------------------|-------|
| Security headers / XSS / CORS / Retire.js / secrets / JWT | **Yes** | Browser-context or DOM-based; mocks work |
| Cookie security | **Yes** | Via `SetCookie` / jar |
| Source map *reference* in HTML/inline script | **Yes** | `.map` *file accessibility* probe uses `HttpClient` → bypasses WebView mocks |
| `CheckLinks` broken external | **Yes** (DNS fail) | Uses `.invalid` TLD; no mock needed |
| `JsAudit` / some bundle fetches | Partial | Server-side `HttpClient` may bypass mocks |
| SQLi / IDOR / CSRF / mass-assignment true-positives | **No** (structural) | Need differential responses; static mock returns same body for baseline and payload |
| OIDC discovery when analyzer uses `HttpClient` | Partial | Browser `Fetch` to mocked discovery works; full probeEndpoints may DNS-fail |
| Console capture on mocked HTTPS | Needs explicit hook | Product injects console hook only when `NavigationCompleted.IsSuccess`; fixtures re-install hook then log |
| GUI | Out of scope | Manual |

Re-run calibration (optional):

```powershell
$exe = "src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe"
$tmp = "$env:TEMP\trowser-cal.csx"
(Get-Content tests\regression\_prelude.csx -Raw) + "`n" + (Get-Content tests\regression\_calibration\calibrate-mocks.csx -Raw) |
  Set-Content $tmp -Encoding UTF8
& $exe --run $tmp --session cal-reg --timeout 180 --output "$env:TEMP\trowser-cal.out.txt"
```

## Relation to other test folders

| Folder | Role |
|--------|------|
| **`tests/regression/`** (this suite) | Automated offline safety net — prefer this |
| [`src/Trowser.ApiTests`](../../src/Trowser.ApiTests/) | REST/MCP integration smoke and OpenAPI sweeps (see [`tests/README.md`](../README.md)) |
| Embedded `TrowserSmokePass` quicktest | Manual in-app scripting smoke (offline mock); complements this suite |
## Design notes

- **No priority on GUI** — CLI hidden window only.
- **CI** — GitHub Actions runs regression `01–07` on every push; full suite via `.\scripts\test.ps1 -Level full` or `.\tests\regression\run-regression.ps1` locally.
- **Positive + clean twin** reduces false-positive regressions.
- Runner uses a unique `--session` per test (not `--ephemeral`) to avoid WebView2 lockfile cleanup races on exit.
