# Trowser automated tests

Layered coverage for open-source contributors. GUI is manual; APIs and scripting are automated.

**Platform:** automated browser tests require **Windows**, **.NET 8**, and **WebView2** (preinstalled on most Windows 10/11). Unit/contract tests in `Trowser.Tests` also run on Windows; they target `net8.0-windows` like the app.

## Quick start (matches push CI)

```powershell
.\scripts\test.ps1 -Level smoke
```

| Level | What runs |
|-------|-----------|
| `quick` | `Trowser.Tests` only (no WebView2 host) |
| `smoke` | quick + ApiTests `Category=Smoke` + regression `01–07` |
| `full` | smoke + ApiTests sweeps + full regression (nightly breadth) |

Set `TROWSER_EXE` to point at a specific `Trowser.exe` if Release/Debug discovery picks the wrong build.

## Test categories (xUnit traits)

| Trait | CI | Use |
|-------|-----|-----|
| (none) | Every push | Unit + static contracts in `Trowser.Tests` |
| `Category=Smoke` | Every push | Fast REST/MCP integration; one shared `--serve` instance |
| `Category=Sweep` | Nightly | OpenAPI fuzz, auth matrix, safe-mode sample |
| `Category=Quarantine` | **Not** in CI | Work-in-progress or flaky tests — fix before relying on them |

Filter examples:

```powershell
dotnet test src/Trowser.ApiTests/Trowser.ApiTests.csproj -c Release --filter "Category=Smoke"
dotnet test src/Trowser.ApiTests/Trowser.ApiTests.csproj -c Release --filter "Category!=Quarantine"
```

## Layers

| Layer | Location | CI |
|-------|----------|-----|
| **Unit + analyzers** | [`src/Trowser.Tests`](../src/Trowser.Tests/) | Every push (`build.yml`) |
| **Static contracts** | Same project: script compile, OpenAPI vs index, MCP dispatch | Every push |
| **API smoke** | [`src/Trowser.ApiTests`](../src/Trowser.ApiTests/) `Category=Smoke` | Every push |
| **Offline regression** | [`tests/regression`](regression/) | Push subset `01–07`; full suite nightly |
| **OpenAPI sweeps** | ApiTests `Category=Sweep` | Nightly |
| **Manual smoke** | Quicktest `TrowserSmokePass` (offline mock) | Manual |

## Run locally (manual commands)

```powershell
dotnet build Trowser.sln -c Release

dotnet test src/Trowser.Tests/Trowser.Tests.csproj -c Release

dotnet test src/Trowser.ApiTests/Trowser.ApiTests.csproj -c Release --filter "Category=Smoke"

.\tests\regression\run-regression.ps1
```

Headless API hosting: `Trowser.exe --serve --api --api-port <port> --api-key <key> --session <name> --nosplash`, or [`scripts/start-serve.ps1`](../scripts/start-serve.ps1).

**Fast regression loop** (API already running):

```powershell
.\scripts\start-serve.ps1          # prints port + key
.\tests\regression\run-regression.ps1 -Fast -Port 6923 -Key "<key from serve>"
```

## If browser smoke fails on GitHub Actions

- Workflow uses `windows-latest` and builds **Release** before ApiTests.
- WebView2 runtime is normally preinstalled; if a job reports WebView2 missing, install from [Microsoft WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) or use a repo-local fixed runtime under `webview2-runtime/` (see `scripts/download-webview2-runtime.ps1` if present).
- Download the **test-results** artifact on failure; regression output is in `tests/regression/results.txt` when uploaded.

## Adding tests

### Regression oracle (preferred for product behavior)

Add a `.csx` under `tests/regression/functional/` or `security/` using helpers in `_prelude.csx` (`SetupPage`, `SecureHeaders`, …). Prefer a **clean twin** fixture when testing scanners.

### REST/MCP parity row

1. Add a case id and implementation in [`ParityCatalog.cs`](../src/Trowser.ApiTests/ParityCatalog.cs) (`CaseIds` + `RunAsync` switch).
2. Start the case with `MockFixtures.SeedExamplePageAsync` (or custom mocks) so shared browser state does not leak.
3. Keep `[Trait("Category", "Smoke")]` on `TransportParityTests`.

### New REST routes / MCP tools

Follow the recipe in [ARCHITECTURE.md](../ARCHITECTURE.md#add-a-rest-route-with-a-matching-mcp-tool). Run `scripts/regen-docs.ps1` (index + OpenAPI); keep stub count ≤ [`tests/baselines/openapi-stubs.txt`](baselines/openapi-stubs.txt) or add real schemas. List blocked operations in `SafeModePolicy.cs`.

## Ratchets

- **OpenAPI stubs**: count of placeholder operations must not exceed the baseline file.
- **MCP dispatch**: every `Tool("…")` must have a matching arm in `McpHandler.Protocol.cs` (see `McpToolSchemaTests`).

## Coverage gap list (good first issues)

```powershell
.\scripts\api-coverage-report.ps1
```

Writes [`tests/api-coverage.md`](api-coverage.md) — REST/MCP surface not referenced by regression and/or ApiTests.
