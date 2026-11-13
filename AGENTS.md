# Working on Trowser

Instructions for coding agents (Cursor, Copilot, Claude, Codex, and others) changing this repository. People are welcome to read it too; [CONTRIBUTING.md](CONTRIBUTING.md) is the human version.

Trowser is a Windows desktop browser for testing web applications: WPF + WebView2 on .NET 8, `win-x64` only. One automation engine is exposed three ways — a localhost REST API, MCP (JSON-RPC on the same port), and C# scripts run by Roslyn. Your job in this repo is to change that product, not to drive it; how to *use* Trowser as a browser is in [trowserkit/trowser.mdc](trowserkit/trowser.mdc).

Read [ARCHITECTURE.md](ARCHITECTURE.md) before your first non-trivial change. It maps the code and has step-by-step recipes for the common changes.

## Commands

All from the repository root, in PowerShell. Windows only.

| Task | Command |
|------|---------|
| Build (what CI does) | `dotnet build Trowser.sln -c Release -warnaserror` |
| Unit and contract tests, plus doc drift check (no browser needed) | `.\scripts\test.ps1 -Level quick` |
| What push CI runs (needs WebView2) | `.\scripts\test.ps1 -Level smoke` |
| Everything, including ApiTests sweeps and the full regression (local; GitHub nightly is unit-only) | `.\scripts\test.ps1 -Level full` |
| One unit test class | `dotnet test src\Trowser.Tests -c Release --filter "FullyQualifiedName~SafeModePolicyTests"` |
| Offline regression suite | `.\tests\regression\run-regression.ps1` (subset: `-Filter "03-*"`) |
| Regenerate the API index and OpenAPI after an API change | `.\scripts\regen-docs.ps1` |
| Check generated docs are current | `.\scripts\regen-docs.ps1 -Check` |
| Run the built app headless with REST/MCP on | `.\scripts\start-serve.ps1` (prints port and key) |

`test.ps1` builds first unless you pass `-NoBuild`. Warnings are errors in CI, so build with `-warnaserror` locally.

Prerequisites: .NET 8 SDK, PowerShell 7 (`pwsh`) for the doc generators, Python 3 (standard library only) for the OpenAPI sync, WebView2 Runtime for anything that launches `Trowser.exe`.

## Rules that are not optional

- **Safe mode is a security boundary.** A new route or MCP tool that runs code, sends raw HTTP, changes session state, or probes actively must be listed in `src/Trowser/Api/SafeModePolicy.cs`. One entry covers REST, MCP, the built-in Chat, batches, and scenarios.
- **Safety modes are part of the contract.** A security probe that can mutate server state runs only at `active` or `aggressive`. Default is `safe`.
- **Page content is untrusted.** Anything from a page that reaches generated C#, HTML reports, file paths, or JavaScript you inject must be escaped or validated where it is written. Look at `HtmlExportText`, `ExportPathGuard`, and `ScriptRecorder.Escape` before inventing your own.
- **One engine, three surfaces.** Put behavior in `AutomationContext` (or a service it calls), then expose it over REST and MCP. Do not add logic that only the GUI, only MCP, or only scripts can reach.
- **Do not edit `CHANGELOG.md`.** The maintainer writes it.
- **The `.gitignore` is a whitelist.** A new file outside `src/`, `tests/`, `scripts/`, `trowserkit/`, `securitykit/`, `licenses/`, or `.github/` is silently ignored until you add an exception there.
- **No secrets or customer data** in source, tests, fixtures, or commit messages. Use the regression fixture host `https://trowser-regression.test`.
- **Third-party code keeps its licence.** Do not strip headers from files in `src/Trowser/Resources/`. A vendored library also goes into `licenses/` and `licenses/THIRD_PARTY_LICENSES.md`.

## Before you say you are done

1. `.\scripts\test.ps1 -Level quick` passes. Run `smoke` if you touched anything that runs in the browser; run the full regression if you touched navigation, scripting, mocks, intercepts, audits, or scanners.
2. If you added or renamed a REST route or MCP tool: `.\scripts\regen-docs.ps1`, and describe the behavior in `trowserkit/trowser-api-reference.md`. Commit the regenerated files with the change.
3. Exercise the change on the built `Trowser.exe`, not just in unit tests. Start it with `.\scripts\start-serve.ps1` and call your route or tool, or write a `.csx` and run `Trowser.exe --run my-check.csx`. Check that the intended behavior is there and that nothing next to it broke.

A regression failure is a signal, not a verdict: the product may be wrong, or the oracle may need to follow an intended behavior change. Say which in the pull request.

## Navigating the code

- The four central classes are split into partial files by feature: `TrowserApiServer.*.cs` (REST, ~24k lines), `AutomationContext.*.cs` (engine, ~14k), `McpHandler.*.cs` (MCP, ~10k), `MainWindow.xaml.*.cs` (GUI, ~9k). Several single files are 2,000–6,500 lines. Do not read them whole; search for the route string (`"/api/key"`), the tool name (`"browser_press_key"`), or the method name, then read around the hit.
- `src/Trowser/Security/` holds ~440 files. [src/Trowser/Security/README.md](src/Trowser/Security/README.md) groups them by bug class.
- MCP tool `browser_foo_bar` conventionally wraps `POST /api/foo-bar`. Follow it: `SafeModePolicyTests` relies on that pairing to check REST and MCP are blocked alike. If your names differ, add the pair to `Get-McpRestHint` in `scripts/generate-api-index.core.ps1`.
- All WebView2 calls must run on the UI thread. `AutomationContext` already marshals through `Dispatcher.InvokeAsync`; reuse its `RunJs` / `RunJsAsync` helpers instead of calling `CoreWebView2` directly.
- Contract tests read source files and find the repo by walking up to `Trowser.sln`. If one fails after you moved code, it is probably parsing a file you changed (`McpToolSchemaTests`, `SafeModePolicyTests`, `ScriptCompileTests`, `OpenApiSpecTests`).
- PowerShell's `-replace`, `-match`, and `-eq` are case-insensitive. Use `-creplace` / `-cmatch` when case matters.

## Pull requests

Describe the tester-visible change and how you tested it ([.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)). Keep the diff focused: no drive-by reformatting, no regenerated files that your change did not affect, no test output. Match the style of the file you are editing.
