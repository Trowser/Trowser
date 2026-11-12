# Trowser API — Interactive Swagger Documentation

This folder contains an interactive API explorer for the Trowser REST API.
It lets you browse every endpoint, see examples, and **try them live** against a running Trowser instance — all from your browser.
Note that the API design is LLM-first, and might be cumbersome for a human to work with.

![Swagger UI](https://img.shields.io/badge/OpenAPI-3.0-green) ![Endpoints](https://img.shields.io/badge/endpoints-partial-yellow)

> **Note:** This OpenAPI spec covers a subset of the REST API. For the complete list, use the auto-generated [trowser-api-index.md](../trowser-api-index.md) or `GET /api` on a running instance.

---

## What you get

- **Browse** a subset of API endpoints organized by category (full list: [trowser-api-index.md](../trowser-api-index.md))
- **Try it out** — send real requests to Trowser and see the responses
- **Authorization** — paste your API key once, and all requests include it
- **Examples** — pre-filled request bodies for common operations
- **Import** — use the same `openapi.yaml` file in Postman, Bruno, or any OpenAPI tool

---

## Getting started

### 1. Start Trowser

Launch Trowser normally. Start the API server from status bar, defaults to port **6923**.
Select Settings in the menu and copy the API key.

### 2. Serve the Swagger UI

The Swagger UI page needs a small local web server to load the API spec file.
The easiest way is with **npx** (comes with Node.js):

```
npx serve .
```

Run this command **from this folder** (`trowserkit/swagger`).

> **What is npx?** It's a tool that comes with [Node.js](https://nodejs.org/).
> If you don't have Node.js installed, download the LTS version from https://nodejs.org/ — the installer takes about 2 minutes.
> After installing, open a **new** terminal window so the `npx` command is available.

When `npx serve .` starts, it will show a URL like `http://localhost:3000`.
Open that URL in your web browser.

<details>
<summary><strong>Alternative: Python (if you have Python but not Node.js)</strong></summary>

```
python -m http.server 3000
```

Then open `http://localhost:3000` in your browser.

</details>

<details>
<summary><strong>Alternative: PowerShell one-liner (no extra tools needed)</strong></summary>

```powershell
$listener = [System.Net.HttpListener]::new(); $listener.Prefixes.Add("http://localhost:3000/"); $listener.Start(); Write-Host "Swagger UI at http://localhost:3000/ (Ctrl+C to stop)"; while ($listener.IsListening) { $ctx = $listener.GetContext(); $file = if ($ctx.Request.Url.LocalPath -eq "/") { "index.html" } else { $ctx.Request.Url.LocalPath.TrimStart("/") }; $path = Join-Path $PSScriptRoot $file; if (Test-Path $path) { $bytes = [IO.File]::ReadAllBytes($path); $ext = [IO.Path]::GetExtension($path); $ctx.Response.ContentType = @{".html"="text/html";".yaml"="text/yaml";".yml"="text/yaml";".json"="application/json";".css"="text/css";".js"="application/javascript"}[$ext]; if (-not $ctx.Response.ContentType) { $ctx.Response.ContentType = "application/octet-stream" }; $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length) } else { $ctx.Response.StatusCode = 404 }; $ctx.Response.Close() }
```

Run this from the `trowserkit/swagger` folder. Then open `http://localhost:3000`.

</details>

### 3. Authorize

1. Click the green **Authorize** button near the top of the page
2. Paste your Trowser API key (from the status bar tooltip)
3. Click **Authorize**, then **Close**

All subsequent requests will include your API key automatically.

### 4. Try it out

1. Click any endpoint to expand it (e.g., **GET /api/state**)
2. Click the **Try it out** button
3. Edit the parameters or request body if needed
4. Click **Execute**
5. See the response below — the actual data from your Trowser session

### Suggested first steps

| # | What to try | Why |
|---|-------------|-----|
| 1 | `GET /api/ping` | Confirm the connection works (no auth needed) |
| 2 | `GET /api/state` | See the full page snapshot with interactive elements |
| 3 | `POST /api/navigate` with `{"url": "https://example.com"}` | Navigate the browser |
| 4 | `GET /api/state` again | See the updated page state with ref numbers |
| 5 | `POST /api/click` with `{"ref": 0}` | Click the first interactive element |
| 6 | `POST /api/accessibility` with `{}` | Run a WCAG accessibility audit |

---

## Using with Postman or Bruno

The `openapi.yaml` file can be imported directly into API tools:

**Postman:**
File → Import → drag in `openapi.yaml` → all endpoints appear as a collection

**Bruno:**
Collection → Import Collection → OpenAPI V3 Spec → select `openapi.yaml`

Both tools will import all 108 endpoints with examples, descriptions, and the auth scheme.

---

## Regenerating `openapi.yaml`

After REST routes change, refresh the index and OpenAPI spec from the repo root:

```powershell
.\scripts\generate-api-index.ps1
.\scripts\update-openapi-from-index.ps1
```

The update script runs Python sync/validate, then **`OpenApiSpecTests`** in `Trowser.Tests` as the .NET gate. Stub count must stay within `tests/baselines/openapi-stubs.txt`.

## Files in this folder

| File | Purpose |
|------|---------|
| `openapi.yaml` | The OpenAPI 3.0 specification — source of truth for the API |
| `index.html` | Swagger UI page that loads the spec |
| `README.md` | This file |

---

## Troubleshooting

**"Failed to load API definition"** — You opened `index.html` directly as a file (`file://...`).
Browsers block loading local files for security reasons. Use one of the server methods above.

**"401 Unauthorized" on every request** — Click **Authorize** and paste your API key.
Find it by hovering over the API indicator in Trowser's status bar.

**"Connection refused"** — Make sure Trowser is running and the API is enabled.
The API indicator in the status bar should show the port number (default: 6923).

**Port conflict with `npx serve`** — If port 3000 is taken, use a different port:
```
npx serve . -l 8080
```
Then open `http://localhost:8080`.
