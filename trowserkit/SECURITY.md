# Trowser Security Model

Trowser is a **test automation tool** that provides an HTTP API for controlling a live browser session. This document describes its threat model, security mechanisms, and guidance for safe usage.

Trowser is a **full-trust local host**: anyone who can call the API (valid bearer key, or auth disabled) can drive the browser, run page JavaScript, run C# in the Trowser process, and make HTTP requests with the session’s cookies. The controls below limit *who can reach that API* and *which operations remain available in `--safe`*. They are not a sandbox.

## Intended Use

Trowser is designed for:
- **Manual testers** exploring web applications via the browser UI
- **Automated test suites** running C# scripts in CI/CD pipelines
- **LLM agents** (Cursor, Claude, etc.) driving a browser via the REST API or MCP

It is **not** intended as a general-purpose web browser for daily browsing.

Use it only against systems you are authorized to test.

## Threat Model

### What we protect against

| Threat | Mitigation |
|--------|------------|
| **Remote attackers** accessing the API | Listener binds to `localhost` only — not reachable from other machines |
| **DNS rebinding** (attacker page rebound to `127.0.0.1`) | Requests whose `Host` is not `localhost`, `127.0.0.1`, or `::1` receive **403**, even if API-key auth is off |
| **Malicious web pages** reading API responses | CORS reflects `Origin` only for loopback origins; other origins get `Access-Control-Allow-Origin: http://localhost` (not `*`) |
| **Unauthorized local tools** controlling the browser | Bearer API key on all requests except `GET /api/ping` (default: required) |
| **Accidental navigation** off the target | Navigation Guard (`--scope`); default is `*.*` (no restriction) |
| **The most dangerous API operations** on untrusted sites | `--safe` / Settings safe mode blocks JS execution, C# scripting, mocks, intercepts, in-page fetch, most scanners, and cookie/storage writes — see [Safe Mode](#3-safe-mode---safe) for gaps |

### What we do NOT protect against

| Threat | Rationale |
|--------|-----------|
| **Any local caller with the API key** | The key is the privilege boundary. With it, a client has full automation of this browser session. |
| **Malicious processes on the same machine** that can read the key | Keys may appear in Settings UI, MCP config, `%APPDATA%\Trowser\api-user.json` (if persisted), or `--api-key` process arguments. Local malware can already do worse. |
| **API key requirement turned off** | Settings can disable the key. If the key is empty or `RestApiKeyRequired` is false, `IsApiKeyValid` accepts every request. |
| **Scripts the user runs** (`--run`, Script Console, Quicktests, `POST /api/execute-script`) | Roslyn runs in-process with `AutomationContext`. The assembly allowlist is **not** a security boundary. |
| **Content inside WebView2** | Default Chromium sandbox. Pages run their own JavaScript. The API can inject more. |
| **Secrets in journals / network logs** | Authenticated `GET /api/journal` and `GET /api/network` can contain request bodies, cookies, and tokens. Nothing is redacted. |

## Security Mechanisms

### 1. API Key Authentication

Every API request except `GET /api/ping` must include a valid key when the requirement is on and a key is configured:

```
Authorization: Bearer <api-key>
```

MCP (`POST /mcp`) uses the same Bearer check as REST. An empty MCP probe body returns **202** after auth.

**Defaults:** `RestApiKeyRequired` is `true`. A 48-character key (`trowser_` + 40 hex chars from `RandomNumberGenerator`) is generated each start unless you pass `--api-key` or enable **Keep API key for next session**.

**Key sources (first match wins):**
- `--api-key <key>` on the command line (visible to other local processes via WMI / process listings)
- Process-level `TROWSER_API_KEY` injected by PeerLauncher (cleared after read; a persistent User/Machine `TROWSER_API_KEY` is ignored so Settings can persist a key)
- `%APPDATA%\Trowser\api-user.json` → `restApiKey` when **Keep API key for next session** is on
- Otherwise a new random key

Prefer env injection for peers (already implemented). Prefer `--api-key` or Keep-API-key for MCP/CI so the client config stays stable. Do not commit mcp.json that embeds a live key.

**Auth can be disabled.** Settings → API Key (required) writes `restApiKeyRequired`. If that flag is false, every local non-browser caller is authorized. Use that only on an isolated machine, briefly. Web pages are still refused (see §2). A required but empty key rejects every request; clearing the key field in Settings generates a new one.

**Unauthenticated:**
- `GET /api/ping` — `{ alive, port, busy, currentOperation, note }` — no page URL/title (those require auth on `/api/state` / `/api/info`)
- `OPTIONS` — CORS preflight (204)

**Authenticated but gate-bypassing:** `POST /api/abort` and `POST /api/force-navigate` still require the key. They skip the 60s operation lock so a stuck session can be recovered.

**Without a valid key:** HTTP 401 `"Unauthorized"`.

### 2. CORS and Host checks

- **Host:** only `localhost`, `127.0.0.1`, `::1` (with or without port). Anything else is 403 before auth.
- **Origin / Fetch Metadata:** a request with a non-loopback `Origin` (including `null`, sent by sandboxed iframes and `file://` pages) or `Sec-Fetch-Site: cross-site` is 403 before auth. CORS alone would only hide the response; a no-cors `text/plain` POST from any web page would still run. Non-browser clients send neither header.
- **CORS:** `Access-Control-Allow-Origin` is the request `Origin` when that origin is loopback; otherwise `http://localhost`. `Authorization` is allowed so a local page that already has the key can call the API. A random internet origin cannot read responses.

Any other process on `http://localhost:*` that obtains the key is in the same trust zone.

### 3. Safe Mode (`--safe`)

Defense-in-depth when the browser may visit untrusted sites. It is one **explicit operation blocklist** (`SafeModePolicy` in `src/Trowser/Api/SafeModePolicy.cs`) applied to REST (any non-GET method, checked before gate-free shortcuts), MCP tools (external and built-in Chat, including when safe mode is toggled at runtime), `/api/batch` and `/api/test-scenario` steps. Blocked REST calls return HTTP 403; blocked tools return an MCP error. A unit test checks every blocked route against its MCP tool and vice versa.

**Blocked (categories — not a complete inventory):**
- `POST /api/execute-js`, `POST /api/execute-script`, Surprise Me
- Network mocks and intercepts (including continue / fulfill / abort / replay)
- Cookie and storage **writes**
- `POST /api/fetch`, `/api/fetch/batch`, `/api/fetch-raw`, `/api/fetch-direct` (in-page, raw TCP, or server-side)
- `PUT`/`DELETE /api/header-overrides` and `browser_header_overrides` with a write action
- `POST /api/upload`, `/api/fuzz`, `/api/load-test`
- Almost all mutating / active security scanners (SQLi, XSS, SSTI, IDOR, smuggling, JWT forge, auto-scan, …) and client-side active audits
- Security playbook runs (`POST /api/orchestrate/{id}`, `browser_orchestrate_run`); dry-run stays allowed
- Race Lab run / baseline / synchronize
- Identity capture / apply (including `/api/peer/identity/apply`) and `POST /api/authz/role-matrix`
- Client certificate add / remove / set active
- WebSocket send / close / audit / fuzz / CSWSH
- Disk export of journal / HAR / reports (`ExportPathGuard` refuses writes in safe mode; see Filesystem helpers)

**Still allowed (by design):** navigation, click, type, scroll, hover, keys, screenshots, page/element reads, accessibility and other passive audits, console/network **reads**, assertions, tabs, viewport, Shadow, OOB callback watch, `POST /api/security/chain-analyze`.

**Also still allowed (easy to miss — not on the blocklist):**
| Endpoint | Why it matters |
|----------|----------------|
| `POST /api/security/attack-surface` | Can emit outbound OpenAPI / JS / artifact probes (`includeOpenApiProbes` defaults true) |
| `POST /api/authz/probe`, `/diff`, `/fuzz`, `/boundary` | Outbound authenticated HTTP; only `/api/authz/role-matrix` is blocked |
| `POST /api/peer/fetch`, `/api/peer/navigate`, … | Peer paths are gate-free; only `/api/peer/identity/apply` is safe-blocked. Peers must still be localhost |
| `POST /api/identity/handoff` | Not on the blocklist |

The canonical list is `SafeModePolicy.BlockedOperations`. The short table in [trowser-api-reference.md](trowser-api-reference.md) is a summary, not the source of truth.

**`--safe` does not wrap CLI scripts.** `Trowser.exe --run test.csx` always executes the script with full `AutomationContext`. Safe mode applies to the REST/MCP server, not to `--run`.

**Enabling:** `Trowser.exe --api --safe`, or Settings → Security → Safe mode. Can be toggled at runtime (applies to REST, external MCP and built-in Chat). The check runs once before the operation gate; toggling during a 60s wait is a small TOCTOU.

### 4. Scanner `safetyMode` (separate from `--safe`)

Security-testing endpoints take a JSON `safetyMode`: `passive` → `safe` (default) → `active` → `aggressive`. Most mutating scans require `"safetyMode": "active"` (`confirmBackend: true` is a legacy alias).

CLI ceilings:
- `--safe-probes-only` caps scanners at `safe` (GET/HEAD/OPTIONS, no mutating IDOR / mass-assignment in auto-scan)
- `--dangerous-ok` allows `aggressive` against non-lab hosts; without it, aggressive is limited to localhost / `*.localhost` / `*.local` / `*.test`

`--safe` (process) and `safetyMode` (per request) are **both** enforced when both apply. `--safe` wins by refusing the route before the scanner runs.

### 5. Navigation Guard

Wildcard patterns:

```
https://*.example.com          → https://www.example.com, https://app.example.com/any/path
https://staging.app.com        → that host and sub-paths
*.*                            → no restrictions (default)
```

Applied to address bar, link clicks, API navigation, and in-page navigations. Multiple patterns are comma-separated. Changeable at runtime (Settings → Browser → Navigation Scope, or `--scope`).

**Always allowed:** `about:`, `data:`, `blob:`, `javascript:`, `edge:`. A scoped session can still run `javascript:` URLs.

### 6. Localhost Binding

```
http://localhost:{port}/
```

Default port **6923** (tries the next 9 if busy; `--api-port 0` picks any free port). Only same-machine clients can connect. Peer registration also requires a localhost `baseUrl`.

`--run` does **not** start the API unless you also pass `--api`. In CLI mode the persisted “API server on at next launch” setting is ignored.

### 7. Serialized Operations

Browser-touching API calls take a `SemaphoreSlim(1,1)`. A waiter that cannot acquire the lock in 60 seconds gets HTTP 503 (`blockedBy`, optional dialog hints). MCP gets JSON-RPC `-32000` instead of a bare 503.

**Gate-free (still authenticated except ping):** in-memory reads (console, network, journal, findings, …), `POST /api/fetch-direct`, all `/api/peer/*`, and a few other listed paths. There is **no inbound rate limit**; optional pacing (`maxRequestsPerSecond`) spaces *outbound* work only.

### 8. WebView2 (page) sandbox

Pages use the default Chromium process sandbox: no host filesystem or process launch from page JavaScript.

**TLS:** ordinary browsing uses default certificate validation. Trowser **does** disable certificate validation on:
- **Forward & Edit Response** in the intercept/breakpoint UI
- **`POST /api/fetch-direct`** (`ServerCertificateCustomValidationCallback` always true)

Those outbound requests are not protected against MITM. Use them only toward servers you trust, on a trusted network.

Trowser does not inject a custom Content-Security-Policy into pages.

### 9. Runtime sensor web messages (untrusted evidence)

When the shared **runtime sensor** is installed (`trace-input` with `monitorSinks`, Shadow audit `runtime`, `client-surface`, `postmessage`, client PP), page JavaScript may call `chrome.webview.postMessage({ type: "__trowser_rt", ... })`.

Treat every `__trowser_rt` payload as **untrusted evidence**:
- Events are rate-limited and size-capped in the host (`RuntimeEventLog`)
- They **never** trigger navigation, fetches, scans, or other actions by themselves
- A malicious page can forge sink/listener events — use them for leads and canary proof, then confirm with controlled oracles (`verify-workflow` `sinkReached` / `messageDelivered` / `prototypePolluted`)

Iframe frames are wired via `CoreWebView2.FrameCreated` so child frames (same- and cross-origin) can report via the frame's own `WebMessageReceived`. Cross-origin frames are listed in `/api/frames` with `inspectable` when a WebView2 frame handle is registered; interaction and sensor install in those frames require `safetyMode: active` and respect navigation scope (`outOfScope`).

### 10. C# scripting (full trust)

Roslyn (`ScriptEngine`) runs `.csx` with `AutomationContext` as globals. Referenced assemblies include the Trowser assembly plus `System.Runtime`, `System.Console`, `System.Text.Json`, and `System.Text.RegularExpressions`. `System.IO` / `System.Diagnostics` are not imported.

That allowlist is **not a sandbox**. Scripts can:
- Call every public automation API (navigate, fetch, upload, `Screenshot(path)`, …)
- Reach already-loaded assemblies via reflection
- Write an arbitrary path through `Screenshot(string filePath)` (`Path.GetFullPath` + `Directory.CreateDirectory`; no `ExportPathGuard`)

`POST /api/execute-script` is blocked in `--safe`. `--run`, the Script Console, and User Quicktests are not.

Only run scripts you trust.

### 11. Filesystem helpers

| Surface | Guard |
|---------|--------|
| REST `GET /api/screenshot?filename=` | Sanitized name, contained under the screenshot directory |
| Exports to disk: journal / HAR / report `?path=`, recording `path`, repro `outputPath`, authz shadow `export`, chain-prove `exportTrwPath` | `ExportPathGuard.TryResolve`: no writes in `--safe`; local drive paths only; document extensions only (`.json .har .html .htm .md .txt .log .csv .xml .yaml .yml .sarif .csx .trw .png .jpg .pdf`, or none); never into Startup folders. Outside safe mode, allowed files may still be written anywhere else the user can write |
| Imports and file inputs: journal / authz shadow import, scenario `file`, repro `trwPath` / `bundlePath`, evidence `bundlePath`, SSL `filePath`, `bodyFile` | `ExportPathGuard.TryResolveRead`: local drive paths only. No directory containment |
| `POST /api/screenshot/compare` `before`/`after` | Read as a file only when it is an existing local path, otherwise decoded as base64 |
| `POST /api/upload` `path` / `paths` | Any fully qualified existing file (`--safe`-blocked) |
| Script `Screenshot(path)` | No containment |

All guarded inputs reject UNC shares (`\\host\share`), device paths (`\\?\`, `\\.\`), `file:` URLs and NTFS alternate data streams. Merely probing a UNC path makes Windows authenticate to that host with the user's NTLM credentials, so those values never reach the file system.

### 11a. Outbound HTTP from Trowser itself

- Server-side fetch (`fetch-direct`, authz comparison, peers) follows redirects by hand. Browser cookies are re-scoped per hop. Caller-supplied `Cookie`, `Authorization` and other credential-like headers (names containing token, auth, session, secret, api-key, csrf, xsrf) are dropped once a redirect leaves the original origin. Response bodies are capped at 10 M characters.
- The download re-fetch fallback sends the page's cookies only to the original origin, caps files at 512 MB, and tags saved files with Mark-of-the-Web (Internet zone).
- Probe clients accept any TLS certificate on purpose: testers routinely target staging hosts with self-signed certificates. Calls to third-party services Trowser relies on (osv.dev) use normal certificate validation.
- Regular expressions have a process-wide 5-second match timeout, so a hostile response cannot hang a scanner with catastrophic backtracking.

### 12. Peers

Multi-instance testing registers another Trowser on localhost only. The child process gets `TROWSER_API_KEY` via the environment, not argv.

## Recommended Configurations

### Testing your own application (trusted)

```bash
Trowser.exe --api --scope "https://*.myapp.com"
```

Normal mode, scoped to your domain. Full API access.

### Testing third-party sites (untrusted)

```bash
Trowser.exe --api --safe --scope "https://untrusted-site.com"
```

Safe mode blocks code execution and most probes. Scope keeps the browser on the target. Remember `fetch-direct` and several authz/peer routes still work if a client has the key — do not disable API-key auth in this setup.

### CI/CD pipeline

```bash
Trowser.exe --run tests/suite.csx --url https://staging.myapp.com
```

`--run` executes the script and does not start the REST server. Add `--api --api-key <key>` only if something else must call the API during the run. Treat `--api-key` like a password on the command line.

### MCP client (OpenCode, Cursor, Claude Code)

Prefer **LLM Settings → MCP client config → Copy** (embeds port, mode, and API key). Enable **Keep API key for next session** in Settings (or `--api-key`) so the key stays stable. Keep mcp.json user-level; do not commit secrets.

```json
{
  "mcpServers": {
    "trowser": {
      "url": "http://localhost:6923/mcp?mode=core",
      "headers": {
        "Authorization": "Bearer trowser_your_key_here"
      }
    }
  }
}
```

External MCP defaults to **Core**. For security testing use `?mode=security` (`?mode=full` is an alias of security). Header: `X-Trowser-Mcp-Mode`. See [README — Connect an external MCP agent](README.md#connect-an-external-mcp-agent).

## Known Security Limitations

### `POST /api/fetch-direct`

Gate-free, not blocked by `--safe`, no URL allowlist, attaches browser cookies by default, and skips TLS verification. This is the peer/authz helper for same-machine HTTP with the live session. Treat it as equivalent to “send my cookies anywhere.”

### Authenticated arbitrary file read

`screenshot/compare`, `bodyFile`, and upload `path` can read any file the Trowser process can open. Mitigated only by API-key auth and (for fetch/upload) `--safe`.

### Journal and network logs

`GET /api/journal` stores the raw JSON body of API calls. `GET /api/network?includeHeaders=true&includeBody=true` can return `Set-Cookie` and request bodies. Assume these contain credentials if you typed or probed any.

### LLM API keys stored in plain text

Keys in LLM Settings are plain JSON in `%APPDATA%\Trowser\settings.json` (per-provider endpoint, key, model). They are not encrypted. Any process or user with access to your Windows profile can read them.

- Prefer environment variables (`OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`) — used when the Settings field is empty and never written back to disk
- For GitHub Copilot, Trowser can use `gh auth token`
- Delete `%APPDATA%\Trowser\settings.json` when you no longer need the configuration

### Persisted REST API key

**Keep API key for next session** stores `restApiKey` in `%APPDATA%\Trowser\api-user.json` (plain JSON, same profile ACL).

### SSL certificate validation (breakpoint forward)

**Forward & Edit Response** disables certificate validation on that outbound request (self-signed lab servers). Same MITM caveat as `fetch-direct`.

### Dual-use security payloads

Built-in wordlists and scanner strings (SQLi, XSS, SSTI, XXE, default credentials, nuclei templates, …) exist so Trowser can detect issues in **authorized** targets. They are not 0-days. `safetyMode` and `--safe` exist to keep them off accidental production traffic.

## Reporting Security Issues

Trowser is a local testing tool, not a hosted service. Please still report issues that let a remote page or a caller *without* the API key control the host, read arbitrary files, or disable the localhost/Host/CORS checks.

- Email: [rikard.edgren@thetesteye.com](mailto:rikard.edgren@thetesteye.com)
- Issues: [github.com/Trowser/Trowser/issues](https://github.com/Trowser/Trowser/issues)

Do not file a public issue that includes a live API key, customer hostnames, or exploit details that would harm third parties. Email first if the report depends on those.
