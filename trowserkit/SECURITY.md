# Trowser Security Model

Trowser is a **test automation tool** that provides an HTTP API for controlling a live browser session. This document describes its threat model, security mechanisms, and guidance for safe usage.

## Intended Use

Trowser is designed for:
- **Manual testers** exploring web applications via the browser UI
- **Automated test suites** running C# scripts in CI/CD pipelines
- **LLM agents** (Cursor, Claude, etc.) driving a browser via the REST API or MCP

It is **not** intended as a general-purpose web browser for daily browsing.

## Threat Model

### What we protect against

| Threat | Mitigation |
|--------|------------|
| **Remote attackers** accessing the API | API binds to `localhost` only -- not reachable from other machines |
| **Malicious web pages** calling the API via JavaScript | API key required on all requests; CORS restricted to the requesting origin (not `*`) |
| **Unauthorized local tools** controlling the browser | API key authentication -- only clients with the key can issue commands |
| **Accidental navigation to dangerous sites** | Navigation Guard restricts URLs to configured scope patterns |
| **Arbitrary code execution on untrusted sites** | Safe mode blocks JS execution, C# scripting, network mocking, and cookie manipulation |

### What we do NOT protect against

| Threat | Rationale |
|--------|-----------|
| **Malicious processes on the same machine** with the API key | If malware has the API key, it already has enough access to do worse things (keyloggers, memory readers, etc.). Localhost binding limits the attack surface to the local machine. |
| **Scripts run by the user themselves** | The C# scripting engine intentionally grants full automation access. Users should only run scripts they trust. |
| **Content within the WebView2 sandbox** | Trowser uses the default Chromium sandbox. Pages can execute JavaScript within their own context as in any browser. The risk is that the *API* can inject additional JS. |

## Security Mechanisms

### 1. API Key Authentication

Every API request (except the health-check endpoint `GET /api/ping`) must include a valid API key:

```
Authorization: Bearer <api-key>
```
This can be toggled of in Settings for testing purposes, but only do that temporarily.

**Key lifecycle:**
- A random 48-character key (e.g., `trowser_a1b2c3d4e5f6...`) is auto-generated each time the API server starts
- The key is shown in the API status tooltip in the status bar
- A fixed key can be set via `--api-key <key>` for CI/CD or MCP client configurations
- Keys are never persisted to disk unless set via CLI argument in a script

**What happens without a valid key:**
- Requests receive HTTP 401 with `"Unauthorized"` error
- CORS preflight (`OPTIONS`) requests are allowed without authentication
- `GET /api/ping` is exempt (health-check only, returns `{alive: true}`)

### 2. CORS Policy

The API reflects the requesting `Origin` header rather than using a blanket `Access-Control-Allow-Origin: *`. This means:
- Requests from the same origin (localhost) work normally
- Cross-origin requests from web pages are restricted to the specific origin that sent them
- Even if a page can make a CORS request, it still needs the API key to authenticate

The `Authorization` header is included in `Access-Control-Allow-Headers` so that API-key-authenticated requests can be made from JavaScript.

### 3. Safe Mode

Safe mode is a defense-in-depth mechanism for sessions where the browser may visit untrusted sites. It blocks the most dangerous API operations while keeping read-only inspection and basic interaction working.

**Blocked in safe mode:**

| REST Endpoint | MCP Tool | Risk |
|---------------|----------|------|
| `POST /api/execute-js` | `browser_execute_js` | Arbitrary JS runs in page context -- can access cookies, tokens, localStorage, DOM |
| `POST /api/execute-script` | `browser_run_script` | C# scripts run in the Trowser host process |
| `POST /api/mock` | -- | Network mocking can intercept and modify HTTP responses |
| `POST /api/mock/remove` | -- | Removes mock rules |
| `POST /api/mock/clear` | -- | Clears all mock rules |
| `POST /api/cookies/set` | -- | Cookie manipulation can set session tokens |
| `POST /api/cookies/delete` | -- | Cookie deletion can log users out |
| `POST /api/cookies/clear` | -- | Clearing cookies affects all sites |
| `POST /api/security/firewall-test` | `browser_firewall_test` | Injects test scripts and modifies page elements |
| `POST /api/security/trace-input` | `browser_trace_input` | Types payloads into inputs and submits forms |

**Still allowed in safe mode:** navigation, clicking, typing, scrolling, hovering, key presses, screenshots, reading page text, reading element text/attributes, accessibility audits, console/network inspection, assertions, tab management, viewport changes, security shadow mode (passive analysis), OOB callback detection (passive monitoring).

**Enabling safe mode:**
- CLI: `Trowser.exe --api --safe`
- GUI: Settings > Security > Safe mode checkbox
- Can be toggled at runtime without restarting the API server

### 4. Navigation Guard

The Navigation Guard restricts which URLs the browser can navigate to. It supports simple wildcard patterns:

```
https://*.example.com          → matches https://www.example.com, https://app.example.com/any/path
https://staging.app.com        → matches https://staging.app.com and all sub-paths
*.*                            → no restrictions (default)
```

**Behavior:**
- Applied to all navigations (address bar, link clicks, API calls, JavaScript)
- Internal URLs (`about:`, `data:`, `blob:`, `javascript:`, `edge:`) always pass
- Multiple patterns can be comma-separated
- Can be changed at runtime via Settings > Browser > Navigation Scope

### 5. Localhost Binding

The API server binds exclusively to `localhost`:

```
http://localhost:{port}/
```

This means:
- Only processes on the same machine can connect
- The API is not accessible over the network
- No firewall configuration is needed

### 6. Serialized Operations

All API operations are serialized through a semaphore (one at a time). This prevents:
- Race conditions from concurrent API calls
- Interleaved browser state from multiple clients
- WebView2 threading issues

If the semaphore is held for more than 60 seconds, waiting requests receive HTTP 503.

### 7. WebView2 Sandbox

Trowser uses the default WebView2 (Chromium) configuration:
- Standard Chromium process sandbox
- Default certificate validation (no overrides or bypasses)
- No custom content security policies injected
- No file system access from page JavaScript
- No process execution from page JavaScript

### 8. Script Engine Restrictions

The Roslyn C# scripting engine has a limited set of assembly references:
- `System.Runtime`, `System.Console`, `System.Text.Json`, `System.Text.RegularExpressions`
- Does **not** include `System.IO` or `System.Diagnostics`
- Scripts cannot directly access the file system or launch processes (except through the `Screenshot()` API)

## Recommended Configurations

### Testing your own application (trusted)

```bash
Trowser.exe --api --scope "https://*.myapp.com"
```

Normal mode, scoped to your domain. Full API access for thorough testing.

### Testing third-party sites (untrusted)

```bash
Trowser.exe --api --safe --scope "https://untrusted-site.com"
```

Safe mode blocks code execution. Navigation guard prevents leaving the target site.

### CI/CD pipeline

```bash
Trowser.exe --run tests/suite.csx --url https://staging.myapp.com --api-key "ci-key-12345"
```

Fixed API key for stable configuration. CLI mode disables the API by default.

### MCP client (Cursor, Claude Desktop)

Configure your MCP client to connect to `http://localhost:6923/mcp` with the API key from the status bar tooltip. Example Cursor MCP config:

```json
{
  "mcpServers": {
    "trowser": {
      "url": "http://localhost:6923/mcp",
      "headers": {
        "Authorization": "Bearer trowser_your_key_here"
      }
    }
  }
}
```

## Known Security Limitations

### SSL certificate validation in breakpoint forwarding

When using the **Forward & Edit Response** feature in the breakpoint hit dialog, Trowser disables SSL certificate validation on the outbound HTTP request. This is necessary to forward requests to development/test servers that use self-signed certificates, but it means the forwarded request is not protected against man-in-the-middle attacks. Only use this feature against servers you trust and on trusted networks.

### LLM API keys stored in plain text

LLM API keys configured in Settings are stored as plain JSON in `%APPDATA%\Trowser\settings.json`. They are not encrypted. Any process or user with access to your Windows profile can read them. If this is a concern:
- Prefer environment variables (`OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`) — Trowser reads them when the Settings key field is empty and does not write them to disk.
- For GitHub Copilot, Trowser can use the GitHub CLI (`gh auth token`) so no key needs to be stored at all.
- Delete `%APPDATA%\Trowser\settings.json` when you no longer need the configuration.

## Reporting Security Issues

If you discover a security vulnerability in Trowser, please report it. Since Trowser is a local testing tool (not a hosted service), most vulnerabilities are low-severity, but we still want to know about them.
